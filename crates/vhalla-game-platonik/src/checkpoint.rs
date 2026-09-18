//! Ledger binding without circularity. Each `(realm, epoch)` of a session is
//! one `vhalla_ledger::Ledger`. A seal's order is appended all-or-nothing; the
//! checkpoint commits the tip after the last admitted event; only then is the
//! `Seal` event appended with the checkpoint hash as payload, as the first
//! event of the next segment. An epoch's terminal seal appends no event.

use vhalla_core::{Epoch, PeerId, RealmId, Sequence};
use vhalla_crypto::{peer_id_from_key, VerifyingKey};
use vhalla_ledger::{Checkpoint as LedgerCheckpoint, Error as LedgerError, Event, Ledger};

use crate::ids::{CheckpointHash, GameEventDigest, SessionKey};

/// An event to append: its author, sequence, and digest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OrderedEvent {
    /// Full author key.
    pub author: [u8; 32],
    /// Per-author sequence.
    pub sequence: Sequence,
    /// The event digest, the ledger payload.
    pub digest: GameEventDigest,
}

/// Why a seal could not be applied; the ledger is unchanged afterwards.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SealApplyError {
    /// An append failed (sequence, parent, capacity); state was restored.
    SealApplyFailed(LedgerError),
    /// The derived checkpoint was not accepted.
    Checkpoint(LedgerError),
    /// The author key is not a valid Ed25519 point.
    Author,
}

/// The routing handle of an author key. Never a policy identity.
#[must_use]
pub fn actor(key: &[u8; 32]) -> Option<PeerId> {
    let key = VerifyingKey::from_bytes(key).ok()?;
    if key.is_weak() {
        return None;
    }
    Some(peer_id_from_key(&key))
}

/// One epoch's ledger with the session's genesis convention.
pub struct SessionLedger {
    realm: RealmId,
    epoch: Epoch,
    ledger: Ledger,
    bound: usize,
    host: PeerId,
    seals_appended: u32,
}

impl core::fmt::Debug for SessionLedger {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SessionLedger")
            .field("realm", &self.realm)
            .field("epoch", &self.epoch)
            .field("head", &self.ledger.head())
            .field("height", &self.height())
            .field("seals_appended", &self.seals_appended)
            .finish()
    }
}

impl SessionLedger {
    /// The ledger bound: genesis, every event the seals can append, one per seal.
    #[must_use]
    pub const fn bound(max_events: u32, max_segments: u8) -> usize {
        1 + max_events as usize + max_segments as usize
    }
    /// Opens epoch 0 with a genesis event carrying the session key.
    pub fn open(
        realm: RealmId,
        session: SessionKey,
        host: [u8; 32],
        bound: usize,
    ) -> Result<Self, SealApplyError> {
        Self::open_with(realm, Epoch(0), session.0.to_vec(), host, bound)
    }
    /// Opens `epoch` with a genesis event carrying the anchoring checkpoint hash.
    pub fn open_epoch(
        realm: RealmId,
        epoch: Epoch,
        anchor: CheckpointHash,
        host: [u8; 32],
        bound: usize,
    ) -> Result<Self, SealApplyError> {
        Self::open_with(realm, epoch, anchor.0.to_vec(), host, bound)
    }
    fn open_with(
        realm: RealmId,
        epoch: Epoch,
        payload: Vec<u8>,
        host: [u8; 32],
        bound: usize,
    ) -> Result<Self, SealApplyError> {
        let host = actor(&host).ok_or(SealApplyError::Author)?;
        let mut ledger = Ledger::new(realm, epoch, bound);
        let genesis = Event::new(None, realm, epoch, host, Sequence(0), payload);
        ledger
            .append(genesis)
            .map_err(SealApplyError::SealApplyFailed)?;
        Ok(Self {
            realm,
            epoch,
            ledger,
            bound,
            host,
            seals_appended: 0,
        })
    }
    /// Realm.
    #[must_use]
    pub const fn realm(&self) -> RealmId {
        self.realm
    }
    /// Epoch.
    #[must_use]
    pub const fn epoch(&self) -> Epoch {
        self.epoch
    }
    /// The current tip.
    #[must_use]
    pub fn head(&self) -> Option<vhalla_ledger::EventDigest> {
        self.ledger.head()
    }
    /// Parent-link count of the tip: `event_count - 1`.
    #[must_use]
    pub fn height(&self) -> u64 {
        (self.ledger.event_count() as u64).saturating_sub(1)
    }
    /// The last accepted checkpoint.
    #[must_use]
    pub fn checkpoint(&self) -> Option<LedgerCheckpoint> {
        self.ledger.checkpoint()
    }
    /// `Seal` events appended to this ledger so far.
    #[must_use]
    pub const fn seals_appended(&self) -> u32 {
        self.seals_appended
    }
    /// Appends a seal's order all-or-nothing, derives the checkpoint at the
    /// new tip, and accepts it. On any failure the ledger is restored to its
    /// state before the first append.
    pub fn apply_seal(
        &mut self,
        order: &[OrderedEvent],
    ) -> Result<LedgerCheckpoint, SealApplyError> {
        let snapshot = self.ledger.snapshot();
        let outcome = self.append_all(order);
        match outcome {
            Ok(()) => {}
            Err(error) => {
                self.ledger = Ledger::restore(&snapshot, self.bound)
                    .map_err(SealApplyError::SealApplyFailed)?;
                return Err(error);
            }
        }
        let head = self
            .ledger
            .head()
            .ok_or(SealApplyError::Checkpoint(LedgerError::StaleCheckpoint))?;
        let state_root = self
            .ledger
            .state_root(head)
            .map_err(SealApplyError::Checkpoint)?;
        let checkpoint = LedgerCheckpoint {
            realm: self.realm,
            epoch: self.epoch,
            head,
            state_root,
            height: self.height(),
        };
        if let Err(error) = self.ledger.accept_checkpoint(checkpoint) {
            self.ledger =
                Ledger::restore(&snapshot, self.bound).map_err(SealApplyError::SealApplyFailed)?;
            return Err(SealApplyError::Checkpoint(error));
        }
        Ok(checkpoint)
    }
    /// The checkpoint a seal would produce, without changing this ledger.
    pub fn preview_seal(&self, order: &[OrderedEvent]) -> Result<LedgerCheckpoint, SealApplyError> {
        let mut copy = Self {
            realm: self.realm,
            epoch: self.epoch,
            ledger: Ledger::restore(&self.ledger.snapshot(), self.bound)
                .map_err(SealApplyError::SealApplyFailed)?,
            bound: self.bound,
            host: self.host,
            seals_appended: self.seals_appended,
        };
        copy.apply_seal(order)
    }
    fn append_all(&mut self, order: &[OrderedEvent]) -> Result<(), SealApplyError> {
        for event in order {
            let actor = actor(&event.author).ok_or(SealApplyError::Author)?;
            let entry = Event::new(
                self.ledger.head(),
                self.realm,
                self.epoch,
                actor,
                event.sequence,
                event.digest.0.to_vec(),
            );
            self.ledger
                .append(entry)
                .map_err(SealApplyError::SealApplyFailed)?;
        }
        Ok(())
    }
    /// Appends the `Seal` event after its checkpoint was accepted: the first
    /// event of the next segment, payload the checkpoint hash, host actor.
    pub fn append_seal(
        &mut self,
        host_sequence: Sequence,
        checkpoint: CheckpointHash,
    ) -> Result<(), SealApplyError> {
        let entry = Event::new(
            self.ledger.head(),
            self.realm,
            self.epoch,
            self.host,
            host_sequence,
            checkpoint.0.to_vec(),
        );
        self.ledger
            .append(entry)
            .map_err(SealApplyError::SealApplyFailed)?;
        self.seals_appended += 1;
        Ok(())
    }
    /// Whether every listed key is pairwise distinct under `peer_id_from_key`,
    /// so the ledger's actor namespace stays in bijection with the keys.
    #[must_use]
    pub fn actors_distinct(keys: &[[u8; 32]]) -> bool {
        let mut seen: Vec<PeerId> = Vec::with_capacity(keys.len());
        for key in keys {
            let Some(actor) = actor(key) else {
                return false;
            };
            if seen.contains(&actor) {
                return false;
            }
            seen.push(actor);
        }
        true
    }
}
