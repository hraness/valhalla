//! The session state machine: admission of every game event, the two-phase
//! bind, the reveal checks, the input gate, and seal preparation and commit.
//! The session never runs a program; the receiver replays through the engine
//! between `prepare_seal` and `commit_seal`.

use std::collections::{BTreeMap, BTreeSet};

use vhalla_core::{Epoch, RealmId, Sequence};
use vhalla_witness::bounds::MAX_EVENTS;
use vhalla_witness::codec;
use vhalla_witness::hash::{digest, ManifestHash, ProgramHash};
use vhalla_witness::manifest::{ProgramSlot, TaskManifest, ValidManifest};
use vhalla_witness::model::Program;
use vhalla_witness::vm::RunStatus;
use vhalla_witness::world::EventKind;

use crate::checkpoint::{OrderedEvent, SealApplyError, SessionLedger};
use crate::engine::AdmittedInput;
use crate::ids::{CheckpointHash, GameEventDigest, GameManifestHash, SessionKey, HOST_SALT_DOMAIN};
use crate::manifest::{GameManifest, MissingMember, SessionKind, SlotRole};
use crate::record::{GameRecord, RecordError, RecordKind};
use crate::wire::{
    self, Authority, CaseCheckpoint, Checkpoint, EventBody, ForkReason, GameEvent, SessionOpen,
    WorkSummary,
};

/// Commitment domain of a bind: session key, slot, program hash, salt.
pub const BIND_COMMIT_DOMAIN: &[u8] = b"vhalla/game/bindcommit/v1";
/// Derivation domain of a live seed.
pub const SEED_DOMAIN: &[u8] = b"vhalla/game/seed/v1";
/// Salt contribution of a filled slot.
pub const FILL_SALT_DOMAIN: &[u8] = b"vhalla/game/fillsalt/v1";
/// Encoded bytes one declared input costs in loading work: tick and kind.
pub const INPUT_ENCODED_BYTES: u64 = 8;
/// Most unsealed events one session buffers.
pub const MAX_PENDING: usize = 512;
/// Most unsealed events one author buffers.
pub const MAX_PENDING_PER_AUTHOR: usize = 16;

/// Where the session is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    /// Opened; binds may arrive.
    Opened,
    /// At least one bind seen; no close yet.
    Binding,
    /// The task is revealed; no seal yet.
    Revealed,
    /// `k` segments sealed.
    Running(u8),
    /// The final seal was committed.
    Finished,
    /// Ended without a result.
    Unresolved(ForkReason),
}

/// Why an event is refused. Every rejection leaves the session bit-identical.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum Rejection {
    Record(RecordError),
    Codec(codec::CodecError),
    NotAnEvent,
    WrongSession,
    WrongEpoch,
    SignerIsNotAuthor,
    NotHost,
    NotPlayer,
    NotOwnSlot,
    Frozen,
    Duplicate,
    Equivocation,
    PendingFull,
    AuthorPendingFull,
    SequenceNotIncreasing,
    WrongState,
    BindAfterClose,
    CommitTwice,
    RevealBeforeClose,
    CommitMismatch,
    BindCloseTwice,
    BindCloseMismatch,
    RevealTwice,
    RevealIncomplete,
    RevealMismatch,
    LoadingRule,
    FuelHeadroom,
    NoSuchCase,
    TickBeyondHorizon,
    StaleTick,
    CaseTerminal,
    CaseEventLimit,
    CaseFuelSlack,
    ReplayKindInput,
    UnknownTarget,
    FillHashMismatch,
    NotPaused,
    SealSegment,
    CompetingSeals,
    SealThroughTick,
    SealOrderUnknown,
    SealOrderDuplicate,
    SealOrderSequence,
    SealOrderFrozen,
    SealOrderCaseEventLimit,
    FillOverBind,
    FillNotFallback,
    FillAfterCommit,
    FillNotAllowed,
    ReplaceUnknownSlot,
    ReplaceWrongOld,
    ActorAliasing,
    SealApply(SealApplyError),
    ReplayMismatch,
    Terminal,
}

impl From<RecordError> for Rejection {
    fn from(error: RecordError) -> Self {
        Self::Record(error)
    }
}

impl From<codec::CodecError> for Rejection {
    fn from(error: codec::CodecError) -> Self {
        Self::Codec(error)
    }
}

/// Why a session could not be opened.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum OpenError {
    Manifest(crate::manifest::ManifestError),
    ManifestHash,
    Ruleset,
    Authority,
    Epoch,
    Players,
    ActorAliasing,
    Ledger(SealApplyError),
}

/// The closed commit set and the digest of the `BindClose` that closed it.
type ClosedCommits = (Vec<(u16, [u8; 32])>, GameEventDigest);

/// The final segment's manifest, candidate programs, and through tick.
pub type FinalPlan = (TaskManifest, Vec<(u16, Program)>, u32);

/// A pending (admitted, unsealed) event.
#[derive(Clone, Debug)]
struct Pending {
    digest: GameEventDigest,
    event: GameEvent,
}

/// What the receiver needs to replay a segment before committing its seal.
#[derive(Clone, Debug)]
pub struct SealPlan {
    /// The seal event's digest.
    pub seal: GameEventDigest,
    /// Host sequence of the seal.
    pub host_sequence: Sequence,
    /// Segment index.
    pub segment: u8,
    /// Session-wide through tick.
    pub through_tick: u32,
    /// The ordered events to append.
    pub order: Vec<OrderedEvent>,
    /// The claimed checkpoint hash.
    pub claimed: CheckpointHash,
    /// Every admitted input up to and including this seal, in seal order.
    pub inputs: Vec<AdmittedInput>,
    /// The segment manifest: the revealed task with those inputs declared.
    pub manifest: TaskManifest,
    /// Candidate programs for the open slots, in slot order.
    pub candidate: Vec<(u16, Program)>,
    /// Whether this seal's order replaces a member (epoch bump on commit).
    pub replace: Option<(u16, [u8; 32], [u8; 32])>,
    /// Whether this is the final seal.
    pub is_final: bool,
    /// Inputs admitted per case between the previous seal and this one.
    pub inputs_since_last: [u32; 8],
}

/// Per-case bookkeeping from the last committed checkpoint.
#[derive(Clone, Copy, Debug, Default)]
struct CaseTrack {
    sealed_effective_tick: u32,
    sealed_inputs: u32,
    terminal: bool,
    slack_closed: bool,
    last: Option<CaseCheckpoint>,
}

/// A session at one receiver.
pub struct Session {
    key: SessionKey,
    manifest: GameManifest,
    open: SessionOpen,
    realm: RealmId,
    host: [u8; 32],
    state: State,
    epoch: Epoch,
    slot_owner: BTreeMap<u16, [u8; 32]>,
    claims: BTreeMap<([u8; 32], u64), GameEventDigest>,
    frozen: BTreeSet<[u8; 32]>,
    last_sealed_sequence: BTreeMap<[u8; 32], u64>,
    pending: Vec<Pending>,
    commits: BTreeMap<u16, [u8; 32]>,
    close: Option<ClosedCommits>,
    reveals: BTreeMap<u16, (Program, [u8; 32])>,
    fills: BTreeMap<u16, (ProgramHash, Program)>,
    epoch_orders: u64,
    missing_slot: Option<u16>,
    final_plan: Option<FinalPlan>,
    settled: Option<Verdict>,
    revealed: Option<TaskManifest>,
    inputs: Vec<AdmittedInput>,
    cases: Vec<CaseTrack>,
    through_tick: u32,
    segments: Vec<(u8, u32, CheckpointHash)>,
    committed_seals: BTreeMap<u8, GameEventDigest>,
    ledger: SessionLedger,
    retained: Vec<[u8; 32]>,
    bound: usize,
}

impl core::fmt::Debug for Session {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Session")
            .field("key", &self.key)
            .field("state", &self.state)
            .field("epoch", &self.epoch)
            .field("pending", &self.pending.len())
            .field("segments", &self.segments.len())
            .finish()
    }
}

/// The commitment a player signs before revealing: session key, slot, the
/// program hash of the single-slot candidate, salt.
#[must_use]
pub fn bind_commit(session: SessionKey, slot: u16, program: &Program, salt: &[u8; 32]) -> [u8; 32] {
    commit_digest(
        session,
        slot,
        ProgramHash::of(&codec::encode_candidate(&[(slot, program.clone())])),
        salt,
    )
}

fn commit_digest(
    session: SessionKey,
    slot: u16,
    program: ProgramHash,
    salt: &[u8; 32],
) -> [u8; 32] {
    let mut body = Vec::with_capacity(32 + 2 + 32 + 32);
    body.extend_from_slice(&session.0);
    body.extend_from_slice(&slot.to_be_bytes());
    body.extend_from_slice(&program.0);
    body.extend_from_slice(salt);
    digest(BIND_COMMIT_DOMAIN, &body)
}

/// The host salt commitment carried in `SessionOpen`.
#[must_use]
pub fn seed_commitment(host_salt: &[u8; 32], world: ManifestHash) -> [u8; 32] {
    let mut body = Vec::with_capacity(64);
    body.extend_from_slice(host_salt);
    body.extend_from_slice(&world.0);
    digest(HOST_SALT_DOMAIN, &body)
}

/// The salt a filled slot contributes.
#[must_use]
pub fn fill_salt(fallback: ProgramHash, slot: u16) -> [u8; 32] {
    let mut body = Vec::with_capacity(34);
    body.extend_from_slice(&fallback.0);
    body.extend_from_slice(&slot.to_be_bytes());
    digest(FILL_SALT_DOMAIN, &body)
}

/// A live seed for case `i` from the host salt and the slot salts in slot order.
#[must_use]
pub fn derive_seed(host_salt: &[u8; 32], slot_salts: &[[u8; 32]], case: u8) -> u64 {
    let mut body = Vec::with_capacity(32 + 32 * slot_salts.len() + 1);
    body.extend_from_slice(host_salt);
    for salt in slot_salts {
        body.extend_from_slice(salt);
    }
    body.push(case);
    let digest = digest(SEED_DOMAIN, &body);
    let mut seed = [0_u8; 8];
    seed.copy_from_slice(&digest[..8]);
    u64::from_be_bytes(seed)
}

/// The template of a task: seeds zero, events empty.
#[must_use]
pub fn template_of(task: &TaskManifest) -> TaskManifest {
    let mut template = task.clone();
    for case in &mut template.cases {
        case.seed = 0;
        case.events.clear();
    }
    template
}

impl Session {
    /// Opens a session for a validated manifest and opening.
    pub fn open(
        manifest: GameManifest,
        open: SessionOpen,
        realm: RealmId,
    ) -> Result<Self, OpenError> {
        manifest.validate().map_err(OpenError::Manifest)?;
        if open.manifest != manifest.hash() {
            return Err(OpenError::ManifestHash);
        }
        if open.ruleset != manifest.ruleset || open.realm != realm {
            return Err(OpenError::Ruleset);
        }
        let Authority::Host { key: host } = open.authority else {
            return Err(OpenError::Authority);
        };
        if open.epoch != Epoch(0) {
            return Err(OpenError::Epoch);
        }
        let open_slots: Vec<u16> = manifest.open_slots().collect();
        let mut slot_owner = BTreeMap::new();
        let mut keys = vec![host];
        for player in &open.players {
            if player.key == host || player.slots.is_empty() {
                return Err(OpenError::Players);
            }
            keys.push(player.key);
            for slot in &player.slots {
                if !open_slots.contains(slot) || slot_owner.insert(*slot, player.key).is_some() {
                    return Err(OpenError::Players);
                }
            }
        }
        if slot_owner.len() != open_slots.len() {
            return Err(OpenError::Players);
        }
        if manifest.limits.kind == SessionKind::Replay && !open.players.is_empty() {
            return Err(OpenError::Players);
        }
        if !SessionLedger::actors_distinct(&keys) {
            return Err(OpenError::ActorAliasing);
        }
        let key = open.key();
        let bound = SessionLedger::bound(manifest.limits.max_events, manifest.limits.max_segments);
        let ledger = SessionLedger::open(realm, key, host, bound).map_err(OpenError::Ledger)?;
        let cases = vec![CaseTrack::default(); manifest.loading_work.len()];
        Ok(Self {
            key,
            manifest,
            open,
            realm,
            host,
            state: State::Opened,
            epoch: Epoch(0),
            slot_owner,
            claims: BTreeMap::new(),
            frozen: BTreeSet::new(),
            last_sealed_sequence: BTreeMap::new(),
            pending: Vec::new(),
            commits: BTreeMap::new(),
            close: None,
            reveals: BTreeMap::new(),
            fills: BTreeMap::new(),
            epoch_orders: 0,
            missing_slot: None,
            final_plan: None,
            settled: None,
            revealed: None,
            inputs: Vec::new(),
            cases,
            through_tick: 0,
            segments: Vec::new(),
            committed_seals: BTreeMap::new(),
            ledger,
            retained: Vec::new(),
            bound,
        })
    }
    /// The session key.
    #[must_use]
    pub const fn key(&self) -> SessionKey {
        self.key
    }
    /// The manifest.
    #[must_use]
    pub const fn manifest(&self) -> &GameManifest {
        &self.manifest
    }
    /// The opening.
    #[must_use]
    pub const fn opening(&self) -> &SessionOpen {
        &self.open
    }
    /// The host key.
    #[must_use]
    pub const fn host(&self) -> [u8; 32] {
        self.host
    }
    /// The state.
    #[must_use]
    pub const fn state(&self) -> State {
        self.state
    }
    /// The epoch.
    #[must_use]
    pub const fn epoch(&self) -> Epoch {
        self.epoch
    }
    /// The ledger of the current epoch.
    #[must_use]
    pub const fn ledger(&self) -> &SessionLedger {
        &self.ledger
    }
    /// The revealed task, once revealed.
    #[must_use]
    pub const fn revealed(&self) -> Option<&TaskManifest> {
        self.revealed.as_ref()
    }
    /// Unsealed admitted events.
    #[must_use]
    pub fn pending(&self) -> usize {
        self.pending.len()
    }
    /// Committed seals as `(segment, through_tick, checkpoint)`.
    #[must_use]
    pub fn segments(&self) -> &[(u8, u32, CheckpointHash)] {
        &self.segments
    }
    /// Retained evidence digests.
    #[must_use]
    pub fn retained(&self) -> &[[u8; 32]] {
        &self.retained
    }
    /// The last committed per-case checkpoint values.
    #[must_use]
    pub fn last_case(&self, case: usize) -> Option<CaseCheckpoint> {
        self.cases.get(case).and_then(|track| track.last)
    }
    /// Inputs sealed for a case, counted across every segment and epoch.
    #[must_use]
    pub fn sealed_inputs(&self, case: usize) -> u32 {
        self.cases.get(case).map_or(0, |track| track.sealed_inputs)
    }
    /// Whether the per-seal fuel slack rule has closed a case's inputs.
    #[must_use]
    pub fn slack_closed(&self, case: usize) -> bool {
        self.cases.get(case).is_some_and(|track| track.slack_closed)
    }
    /// The seal digest this session committed for a segment.
    #[must_use]
    pub fn committed_seal(&self, segment: u8) -> Option<GameEventDigest> {
        self.committed_seals.get(&segment).copied()
    }
    fn max_ticks(&self) -> u32 {
        self.revealed
            .as_ref()
            .map(|task| task.cases.iter().map(|case| case.ticks).max().unwrap_or(0))
            .unwrap_or(0)
    }
    fn is_player(&self, key: &[u8; 32]) -> bool {
        self.slot_owner.values().any(|owner| owner == key)
    }
    /// Admits one record carrying a game event. `Seal` events are validated
    /// but not applied: they return a `SealPlan` for the receiver to replay,
    /// and `commit_seal` applies them afterwards.
    pub fn admit(&mut self, record: &GameRecord) -> Result<Admitted, Rejection> {
        if record.kind != RecordKind::Event {
            return Err(Rejection::NotAnEvent);
        }
        record.verify()?;
        let event = wire::decode_game_event(&record.body)?;
        if event.session != self.key || record.session != self.key {
            return Err(Rejection::WrongSession);
        }
        if event.epoch != self.epoch {
            return Err(Rejection::WrongEpoch);
        }
        if record.signer != event.author {
            return Err(Rejection::SignerIsNotAuthor);
        }
        let digest = event.digest();
        // Competing seals. A second host-signed seal for a segment this
        // receiver already committed, carrying a digest the committed seal
        // does not, is a host fork: both seals are retained, the second is
        // not applied, and the session goes unresolved. The check runs before
        // the terminal, claim-table, and sequence gates because the two seals
        // reach two receivers in either order and either one may carry the
        // lower host sequence; running it first is what makes both receivers
        // reach the same verdict from the same pair of records. An exact
        // resend carries the committed digest and falls through to the claim
        // table, which answers `Duplicate`.
        if let EventBody::Seal { segment, .. } = &event.body {
            if event.author == self.host && !matches!(self.state, State::Unresolved(_)) {
                if let Some(committed) = self.committed_seals.get(segment).copied() {
                    if committed != digest {
                        self.retain_fork(committed, digest);
                        self.state = State::Unresolved(ForkReason::CompetingSeals);
                        return Err(Rejection::CompetingSeals);
                    }
                }
            }
        }
        let paused = self.state == State::Unresolved(ForkReason::MemberMissing)
            && self.missing_slot.is_some();
        if matches!(self.state, State::Finished | State::Unresolved(_))
            && !(paused && event.author == self.host)
        {
            return Err(Rejection::Terminal);
        }
        // Claim table: duplicate, equivocation, monotone sequence.
        if let Some(existing) = self.claims.get(&(event.author, event.sequence.0)) {
            if *existing == digest {
                return Err(Rejection::Duplicate);
            }
            self.retained.push(existing.0);
            self.retained.push(digest.0);
            self.frozen.insert(event.author);
            return Err(Rejection::Equivocation);
        }
        if self.frozen.contains(&event.author) {
            return Err(Rejection::Frozen);
        }
        let last = self
            .claims
            .keys()
            .filter(|(author, _)| *author == event.author)
            .map(|(_, sequence)| *sequence)
            .max()
            .unwrap_or(0);
        if event.sequence.0 == 0 || event.sequence.0 <= last {
            return Err(Rejection::SequenceNotIncreasing);
        }
        if matches!(event.body, EventBody::Seal { .. }) {
            let plan = self.prepare_seal(&event, digest)?;
            self.claims.insert((event.author, event.sequence.0), digest);
            return Ok(Admitted::Seal(Box::new(plan)));
        }
        if self.pending.len() >= MAX_PENDING {
            return Err(Rejection::PendingFull);
        }
        if self
            .pending
            .iter()
            .filter(|pending| pending.event.author == event.author)
            .count()
            >= MAX_PENDING_PER_AUTHOR
        {
            return Err(Rejection::AuthorPendingFull);
        }
        self.check_body(&event, digest)?;
        self.apply_body(&event, digest);
        self.claims.insert((event.author, event.sequence.0), digest);
        self.pending.push(Pending { digest, event });
        Ok(Admitted::Pending(digest))
    }
    /// Retains a fork's two digests in ascending byte order, so two receivers
    /// that saw the pair in opposite orders retain identical evidence.
    fn retain_fork(&mut self, one: GameEventDigest, other: GameEventDigest) {
        let (first, second) = if one.0 <= other.0 {
            (one, other)
        } else {
            (other, one)
        };
        self.retained.push(first.0);
        self.retained.push(second.0);
    }
    fn check_body(&self, event: &GameEvent, _digest: GameEventDigest) -> Result<(), Rejection> {
        let from_host = event.author == self.host;
        match &event.body {
            EventBody::BindCommit { slot, .. } => {
                if !self.is_player(&event.author) {
                    return Err(Rejection::NotPlayer);
                }
                if self.slot_owner.get(slot) != Some(&event.author) {
                    return Err(Rejection::NotOwnSlot);
                }
                if !matches!(self.state, State::Opened | State::Binding) {
                    return Err(Rejection::WrongState);
                }
                if self.close.is_some() {
                    return Err(Rejection::BindAfterClose);
                }
                if self.commits.contains_key(slot) {
                    return Err(Rejection::CommitTwice);
                }
                Ok(())
            }
            EventBody::BindReveal {
                slot,
                program,
                salt,
            } => {
                if !self.is_player(&event.author) {
                    return Err(Rejection::NotPlayer);
                }
                if self.slot_owner.get(slot) != Some(&event.author) {
                    return Err(Rejection::NotOwnSlot);
                }
                let Some((closed, _)) = &self.close else {
                    return Err(Rejection::RevealBeforeClose);
                };
                if self.reveals.contains_key(slot) {
                    return Err(Rejection::RevealTwice);
                }
                let expected = commit_digest(
                    self.key,
                    *slot,
                    ProgramHash::of(&codec::encode_candidate(&[(*slot, program.clone())])),
                    salt,
                );
                if !closed.iter().any(|(s, d)| s == slot && *d == expected) {
                    return Err(Rejection::CommitMismatch);
                }
                Ok(())
            }
            EventBody::BindClose { commits } => {
                if !from_host {
                    return Err(Rejection::NotHost);
                }
                if self.close.is_some() {
                    return Err(Rejection::BindCloseTwice);
                }
                if !matches!(self.state, State::Opened | State::Binding) {
                    return Err(Rejection::WrongState);
                }
                let mine: Vec<(u16, [u8; 32])> = self
                    .commits
                    .iter()
                    .map(|(slot, commit)| (*slot, *commit))
                    .collect();
                if *commits != mine {
                    return Err(Rejection::BindCloseMismatch);
                }
                Ok(())
            }
            EventBody::Reveal { task, host_salt } => {
                if !from_host {
                    return Err(Rejection::NotHost);
                }
                if self.revealed.is_some() {
                    return Err(Rejection::RevealTwice);
                }
                self.check_reveal(task, host_salt)
            }
            EventBody::Input { case, tick, kind } => {
                if !self.is_player(&event.author) {
                    return Err(Rejection::NotPlayer);
                }
                if self.manifest.limits.kind == SessionKind::Replay {
                    return Err(Rejection::ReplayKindInput);
                }
                if let EventKind::ClearMemory { cell } = kind {
                    if self.slot_owner.get(cell) != Some(&event.author) {
                        return Err(Rejection::NotOwnSlot);
                    }
                }
                self.check_input(*case, *tick, kind)
            }
            EventBody::Seal { .. } => Ok(()),
            EventBody::Replace { slot, old, new } => {
                if !from_host {
                    return Err(Rejection::NotHost);
                }
                let paused = self.state == State::Unresolved(ForkReason::MemberMissing)
                    && self.missing_slot == Some(*slot);
                if !matches!(self.state, State::Running(_) | State::Revealed) && !paused {
                    return Err(Rejection::WrongState);
                }
                if self.slot_owner.get(slot) != Some(old) {
                    return Err(Rejection::ReplaceWrongOld);
                }
                let mut keys: Vec<[u8; 32]> = vec![self.host];
                keys.extend(self.slot_owner.values().filter(|k| **k != *old).copied());
                keys.push(*new);
                if !SessionLedger::actors_distinct(&keys) {
                    return Err(Rejection::ActorAliasing);
                }
                Ok(())
            }
            EventBody::Fill {
                slot, program_hash, ..
            } => {
                if !from_host {
                    return Err(Rejection::NotHost);
                }
                let Some(game_slot) = self.manifest.slots.iter().find(|s| s.cell == *slot) else {
                    return Err(Rejection::ReplaceUnknownSlot);
                };
                let SlotRole::Open {
                    fallback: Some(fallback),
                } = game_slot.role
                else {
                    return Err(Rejection::FillNotAllowed);
                };
                if self.manifest.limits.missing_member != MissingMember::Fill {
                    return Err(Rejection::FillNotAllowed);
                }
                if fallback != *program_hash {
                    return Err(Rejection::FillNotFallback);
                }
                if self.revealed.is_none() && self.commits.contains_key(slot) {
                    return Err(Rejection::FillAfterCommit);
                }
                if self.commits.contains_key(slot) || self.reveals.contains_key(slot) {
                    return Err(Rejection::FillOverBind);
                }
                Ok(())
            }
        }
    }
    fn apply_body(&mut self, event: &GameEvent, digest: GameEventDigest) {
        match &event.body {
            EventBody::BindCommit { slot, commit } => {
                self.commits.insert(*slot, *commit);
                self.state = State::Binding;
            }
            EventBody::BindReveal {
                slot,
                program,
                salt,
            } => {
                self.reveals.insert(*slot, (program.clone(), *salt));
            }
            EventBody::BindClose { commits } => {
                self.close = Some((commits.clone(), digest));
                self.state = State::Binding;
            }
            EventBody::Reveal { task, .. } => {
                self.revealed = Some(task.clone());
                self.state = State::Revealed;
            }
            EventBody::Fill {
                slot,
                program_hash,
                program,
                ..
            } => {
                self.fills.insert(*slot, (*program_hash, program.clone()));
            }
            EventBody::Input { .. } | EventBody::Seal { .. } | EventBody::Replace { .. } => {}
        }
    }
    fn check_reveal(&self, task: &TaskManifest, host_salt: &[u8; 32]) -> Result<(), Rejection> {
        // Every open slot revealed or filled; commits closed for live sessions.
        let open_slots: Vec<u16> = self.manifest.open_slots().collect();
        if self.manifest.limits.kind == SessionKind::Live {
            if self.close.is_none() && !open_slots.is_empty() {
                return Err(Rejection::RevealBeforeClose);
            }
            for slot in &open_slots {
                if !self.reveals.contains_key(slot) && !self.fills.contains_key(slot) {
                    return Err(Rejection::RevealIncomplete);
                }
            }
        }
        // The world digest, slots, and contract.
        let template = template_of(task);
        let template_valid =
            ValidManifest::validate(template).map_err(|_| Rejection::RevealMismatch)?;
        if template_valid.hash() != self.manifest.world {
            return Err(Rejection::RevealMismatch);
        }
        if task.contract != self.manifest.contract
            || task.cases.len() != self.manifest.loading_work.len()
            || task.slots.len() != self.manifest.slots.len()
        {
            return Err(Rejection::RevealMismatch);
        }
        for (slot, game_slot) in task.slots.iter().zip(&self.manifest.slots) {
            if slot.cell != game_slot.cell {
                return Err(Rejection::RevealMismatch);
            }
            match (game_slot.role, &slot.fixed) {
                (SlotRole::Fixed, Some(_)) | (SlotRole::Open { .. }, None) => {}
                _ => return Err(Rejection::RevealMismatch),
            }
        }
        // A live task declares no events; a replay task carries the published
        // experiment's own events, which are part of what it replays.
        if self.manifest.limits.kind == SessionKind::Live
            && task.cases.iter().any(|case| !case.events.is_empty())
        {
            return Err(Rejection::RevealMismatch);
        }
        // Seeds and commitment.
        match self.manifest.limits.kind {
            SessionKind::Replay => {}
            SessionKind::Live => {
                if seed_commitment(host_salt, self.manifest.world) != self.open.seed_commitment {
                    return Err(Rejection::RevealMismatch);
                }
                let mut salts = Vec::new();
                for game_slot in &self.manifest.slots {
                    match game_slot.role {
                        SlotRole::Fixed => {}
                        SlotRole::Open { fallback } => {
                            if let Some((_, salt)) = self.reveals.get(&game_slot.cell) {
                                salts.push(*salt);
                            } else if let Some((filled, _)) = self.fills.get(&game_slot.cell) {
                                let _ = fallback;
                                salts.push(fill_salt(*filled, game_slot.cell));
                            } else {
                                return Err(Rejection::RevealIncomplete);
                            }
                        }
                    }
                }
                for (index, case) in task.cases.iter().enumerate() {
                    if case.seed != derive_seed(host_salt, &salts, index as u8) {
                        return Err(Rejection::RevealMismatch);
                    }
                }
            }
        }
        // Loading rule and fuel headroom.
        let template_len = codec::encode_manifest(&template_of(task)).len() as u64;
        for (index, case) in task.cases.iter().enumerate() {
            let expected = match self.manifest.limits.kind {
                SessionKind::Replay => self.manifest.loading_work[index],
                SessionKind::Live => {
                    template_len + u64::from(self.manifest.limits.max_events) * INPUT_ENCODED_BYTES
                }
            };
            if case.loading_work != expected {
                return Err(Rejection::LoadingRule);
            }
            if case.fuel < case.loading_work.saturating_add(MAX_EVENTS as u64 + 1) {
                return Err(Rejection::FuelHeadroom);
            }
        }
        ValidManifest::validate(task.clone()).map_err(|_| Rejection::RevealMismatch)?;
        Ok(())
    }
    fn check_input(&self, case: u8, tick: u32, kind: &EventKind) -> Result<(), Rejection> {
        let Some(task) = &self.revealed else {
            return Err(Rejection::WrongState);
        };
        let Some(spec) = task.cases.get(usize::from(case)) else {
            return Err(Rejection::NoSuchCase);
        };
        // The target must exist in the revealed world, so an input never fails
        // later at segment manifest construction.
        let exists = match kind {
            EventKind::LinkEnabled { id, .. } => task.world.links.iter().any(|l| l.id == *id),
            EventKind::ValveEnabled { id, .. } => task.world.valves.iter().any(|v| v.id == *id),
            EventKind::ClearMemory { cell } => task.world.cells.iter().any(|c| c.id == *cell),
        };
        if !exists {
            return Err(Rejection::UnknownTarget);
        }
        if tick == 0 || tick > spec.ticks {
            return Err(Rejection::TickBeyondHorizon);
        }
        let track = self.cases[usize::from(case)];
        if track.terminal {
            return Err(Rejection::CaseTerminal);
        }
        if tick <= track.sealed_effective_tick {
            return Err(Rejection::StaleTick);
        }
        // The per-case cap is measured against the sealed tally alone and
        // never against the arrival-ordered pending buffer, so which `Input`
        // survives is never a function of arrival order. The cap itself is
        // enforced where `Seal.order` is validated, as
        // `SealOrderCaseEventLimit`.
        if track.sealed_inputs >= MAX_EVENTS as u32 {
            return Err(Rejection::CaseEventLimit);
        }
        if track.slack_closed {
            return Err(Rejection::CaseFuelSlack);
        }
        Ok(())
    }
    /// The candidate programs for the open slots from reveals and fills.
    fn candidate(&self) -> Result<Vec<(u16, Program)>, Rejection> {
        let mut candidate = Vec::new();
        for slot in self.manifest.open_slots() {
            if let Some((program, _)) = self.reveals.get(&slot) {
                candidate.push((slot, program.clone()));
            } else if let Some((_, program)) = self.fills.get(&slot) {
                candidate.push((slot, program.clone()));
            } else {
                return Err(Rejection::RevealIncomplete);
            }
        }
        Ok(candidate)
    }
    /// Validates a seal event without admitting it: what an honest host runs
    /// to derive the checkpoint it must sign, and what the receiver runs
    /// inside `admit`.
    pub fn plan_seal(&self, event: &GameEvent) -> Result<SealPlan, Rejection> {
        self.prepare_seal(event, event.digest())
    }
    fn prepare_seal(
        &self,
        event: &GameEvent,
        digest: GameEventDigest,
    ) -> Result<SealPlan, Rejection> {
        let EventBody::Seal {
            segment,
            through_tick,
            order,
            checkpoint,
        } = &event.body
        else {
            return Err(Rejection::NotAnEvent);
        };
        if event.author != self.host {
            return Err(Rejection::NotHost);
        }
        let Some(task) = &self.revealed else {
            return Err(Rejection::WrongState);
        };
        let paused = self.state == State::Unresolved(ForkReason::MemberMissing)
            && self.missing_slot.is_some();
        if !matches!(self.state, State::Revealed | State::Running(_)) && !paused {
            return Err(Rejection::WrongState);
        }
        if usize::from(*segment) != self.segments.len()
            || *segment >= self.manifest.limits.max_segments
        {
            return Err(Rejection::SealSegment);
        }
        let max_ticks = self.max_ticks();
        if *through_tick <= self.through_tick || *through_tick > max_ticks {
            return Err(Rejection::SealThroughTick);
        }
        let mut seen = BTreeSet::new();
        let mut ordered = Vec::with_capacity(order.len());
        let mut last_sequence: BTreeMap<[u8; 32], u64> = self.last_sealed_sequence.clone();
        let mut inputs = self.inputs.clone();
        let mut since_last = [0_u32; 8];
        let mut counts: Vec<u32> = self.cases.iter().map(|c| c.sealed_inputs).collect();
        let mut replace = None;
        for wanted in order {
            if !seen.insert(*wanted) {
                return Err(Rejection::SealOrderDuplicate);
            }
            let Some(pending) = self.pending.iter().find(|p| p.digest == *wanted) else {
                return Err(Rejection::SealOrderUnknown);
            };
            let ev = &pending.event;
            if self.frozen.contains(&ev.author) {
                return Err(Rejection::SealOrderFrozen);
            }
            let last = last_sequence.get(&ev.author).copied().unwrap_or(0);
            if ev.sequence.0 <= last {
                return Err(Rejection::SealOrderSequence);
            }
            last_sequence.insert(ev.author, ev.sequence.0);
            match &ev.body {
                EventBody::Input { case, tick, kind } => {
                    let index = usize::from(*case);
                    if index >= counts.len() {
                        return Err(Rejection::NoSuchCase);
                    }
                    counts[index] += 1;
                    if counts[index] > MAX_EVENTS as u32 {
                        return Err(Rejection::SealOrderCaseEventLimit);
                    }
                    since_last[index] += 1;
                    inputs.push(AdmittedInput {
                        case: *case,
                        tick: *tick,
                        kind: *kind,
                    });
                }
                EventBody::Fill { slot, .. } => {
                    if self.commits.contains_key(slot) || self.reveals.contains_key(slot) {
                        return Err(Rejection::FillOverBind);
                    }
                }
                EventBody::Replace { slot, old, new } => {
                    replace = Some((*slot, *old, *new));
                }
                _ => {}
            }
            ordered.push(OrderedEvent {
                author: ev.author,
                sequence: ev.sequence,
                digest: *wanted,
            });
        }
        let manifest = {
            let mut m = task.clone();
            for input in &inputs {
                if let Some(case) = m.cases.get_mut(usize::from(input.case)) {
                    case.events.push(vhalla_witness::world::Event {
                        tick: input.tick,
                        event: input.kind,
                    });
                }
            }
            m
        };
        if paused && replace.map(|(slot, _, _)| Some(slot)) != Some(self.missing_slot) {
            return Err(Rejection::NotPaused);
        }
        Ok(SealPlan {
            seal: digest,
            host_sequence: event.sequence,
            segment: *segment,
            through_tick: *through_tick,
            order: ordered,
            claimed: *checkpoint,
            inputs,
            manifest,
            candidate: self.candidate()?,
            replace,
            is_final: *through_tick == max_ticks,
            inputs_since_last: since_last,
        })
    }
    /// Applies a prepared seal after the receiver reproduced its checkpoint:
    /// appends the order, accepts the ledger checkpoint, records the per-case
    /// values, and appends the `Seal` event or opens the next epoch.
    pub fn commit_seal(
        &mut self,
        plan: &SealPlan,
        checkpoint: &Checkpoint,
    ) -> Result<CheckpointHash, Rejection> {
        if checkpoint.hash() != plan.claimed {
            self.retained.push(plan.seal.0);
            self.state = State::Unresolved(ForkReason::ReplayMismatch);
            return Err(Rejection::ReplayMismatch);
        }
        let ledger_checkpoint = self
            .ledger
            .apply_seal(&plan.order)
            .map_err(Rejection::SealApply)?;
        debug_assert_eq!(ledger_checkpoint, checkpoint.ledger);
        let hash = checkpoint.hash();
        // Remove sealed events from pending; update claims and per-case tracking.
        let sealed: BTreeSet<GameEventDigest> = plan.order.iter().map(|e| e.digest).collect();
        self.pending.retain(|p| !sealed.contains(&p.digest));
        for event in &plan.order {
            self.last_sealed_sequence
                .insert(event.author, event.sequence.0);
        }
        self.last_sealed_sequence
            .insert(self.host, plan.host_sequence.0);
        self.inputs = plan.inputs.clone();
        let task = self.revealed.as_ref().expect("sealed after reveal");
        for (index, track) in self.cases.iter_mut().enumerate() {
            let spec = &task.cases[index];
            track.sealed_effective_tick = plan.through_tick.min(spec.ticks);
            track.sealed_inputs += plan.inputs_since_last[index];
            if let Some(case) = checkpoint.cases.get(index) {
                track.last = Some(*case);
                track.terminal = case.status == RunStatus::FuelExhausted
                    || track.sealed_effective_tick >= spec.ticks;
                let slack = spec.fuel.saturating_sub(case.ledger_total);
                let remaining =
                    u64::from(MAX_EVENTS as u32 - track.sealed_inputs.min(MAX_EVENTS as u32));
                if slack < remaining {
                    track.slack_closed = true;
                }
            }
        }
        self.through_tick = plan.through_tick;
        self.segments.push((plan.segment, plan.through_tick, hash));
        self.committed_seals.insert(plan.segment, plan.seal);
        self.epoch_orders += plan.order.len() as u64;
        if plan.is_final {
            self.final_plan = Some((
                plan.manifest.clone(),
                plan.candidate.clone(),
                plan.through_tick,
            ));
            self.state = State::Finished;
            return Ok(hash);
        }
        if let Some((slot, old, new)) = plan.replace {
            let _ = old;
            self.slot_owner.insert(slot, new);
            self.epoch = Epoch(self.epoch.0 + 1);
            self.ledger =
                SessionLedger::open_epoch(self.realm, self.epoch, hash, self.host, self.bound)
                    .map_err(Rejection::SealApply)?;
            self.last_sealed_sequence.clear();
            self.claims.clear();
            self.pending.clear();
            self.epoch_orders = 0;
            self.missing_slot = None;
        } else {
            self.ledger
                .append_seal(plan.host_sequence, hash)
                .map_err(Rejection::SealApply)?;
        }
        self.state = State::Running(plan.segment + 1);
        Ok(hash)
    }
    /// Marks the session unresolved with retained evidence.
    pub fn unresolve(&mut self, reason: ForkReason, evidence: &[[u8; 32]]) {
        self.retained.extend_from_slice(evidence);
        self.state = State::Unresolved(reason);
    }
    /// Pauses on a missing member of `slot` under `MissingMember::Pause`;
    /// only a host `Replace` of that slot, sealed, resumes the session.
    pub fn pause_missing(&mut self, slot: u16, evidence: &[[u8; 32]]) -> Result<(), Rejection> {
        if self.manifest.limits.missing_member != MissingMember::Pause
            || !self.slot_owner.contains_key(&slot)
            || !matches!(self.state, State::Revealed | State::Running(_))
        {
            return Err(Rejection::NotPaused);
        }
        self.missing_slot = Some(slot);
        self.unresolve(ForkReason::MemberMissing, evidence);
        Ok(())
    }
    /// Admitted events sealed into the current epoch's ledger so far.
    #[must_use]
    pub const fn epoch_orders(&self) -> u64 {
        self.epoch_orders
    }
    /// The final segment's manifest, candidate, and through tick, once sealed.
    #[must_use]
    pub const fn final_plan(&self) -> Option<&FinalPlan> {
        self.final_plan.as_ref()
    }
    /// The settlement verdict this receiver holds, if any.
    #[must_use]
    pub const fn settled(&self) -> Option<&Verdict> {
        self.settled.as_ref()
    }
    /// Records a verdict; the receiver decides admissibility and ranking.
    pub fn record_verdict(&mut self, verdict: Verdict) {
        if let Verdict::Unresolved { reason, .. } = &verdict {
            self.state = State::Unresolved(*reason);
        }
        self.settled = Some(verdict);
    }
    /// The previous checkpoint hash, or zero for segment 0.
    #[must_use]
    pub fn parent_checkpoint(&self) -> [u8; 32] {
        self.segments
            .last()
            .map(|(_, _, hash)| hash.0)
            .unwrap_or([0; 32])
    }
    /// The work summary the receiver expects at the next checkpoint.
    #[must_use]
    pub fn work_so_far(&self) -> WorkSummary {
        WorkSummary {
            useful: 0,
            total: 0,
        }
    }
    /// The game manifest hash.
    #[must_use]
    pub fn manifest_hash(&self) -> GameManifestHash {
        self.manifest.hash()
    }
    /// Slots and their current owners.
    #[must_use]
    pub fn slot_owners(&self) -> &BTreeMap<u16, [u8; 32]> {
        &self.slot_owner
    }
    /// The declared fallback for a slot, if any.
    #[must_use]
    pub fn fallback(&self, slot: u16) -> Option<ProgramHash> {
        self.manifest
            .slots
            .iter()
            .find(|s| s.cell == slot)
            .and_then(|s| match s.role {
                SlotRole::Open { fallback } => fallback,
                SlotRole::Fixed => None,
            })
    }
    /// The template hash the session was opened for.
    #[must_use]
    pub const fn world(&self) -> ManifestHash {
        self.manifest.world
    }
    /// Programs the revealed task fixes, by slot.
    #[must_use]
    pub fn fixed_programs(&self) -> Vec<ProgramSlot> {
        self.revealed
            .as_ref()
            .map(|t| t.slots.clone())
            .unwrap_or_default()
    }
}

/// What admission produced.
#[derive(Debug)]
pub enum Admitted {
    /// The event is pending a seal.
    Pending(GameEventDigest),
    /// A seal plan for the receiver to replay and then commit.
    Seal(Box<SealPlan>),
}

/// A settlement verdict this receiver holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// A result the receiver reproduced itself.
    Result {
        /// The final checkpoint.
        checkpoint: CheckpointHash,
        /// Whether the contract passed.
        passed: bool,
        /// Hash of the reproduced receipt.
        receipt: [u8; 32],
    },
    /// An unresolved fork, host signed or receiver derived.
    Unresolved {
        /// Why.
        reason: ForkReason,
        /// Heads named.
        heads: Vec<[u8; 32]>,
        /// Evidence digests named.
        evidence: Vec<[u8; 32]>,
    },
}
