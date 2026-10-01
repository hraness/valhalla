//! The selected-source registry is metadata, never native room authority.

use super::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use vhalla_direct_store::{self as disk, Context as StoreContext, Entry, Record, Store};

const MAGIC: &[u8; 8] = b"VHDPSM01";
const VERSION: u32 = 1;
const IMAGE_LIMIT: usize = 2 * 1024 * 1024;
const LIMITS: disk::Limits = disk::Limits {
    max_records: 100_000,
    max_record_bytes: 32 * 1024 * 1024,
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Binding {
    pub(super) room: Hash,
    pub(super) author: Hash,
    pub(super) nonce: Hash,
    pub(super) created: bool,
    genesis: String,
}
impl Binding {
    pub(super) fn capture(room: &mut RoomSession) -> Result<Self> {
        let status = room.status().map_err(|_| unavailable())?;
        let binding = Self {
            room: Hex(*room.room_id().as_bytes()),
            author: Hex(room.author_key()),
            nonce: Hex(room.creation_nonce()),
            created: status.created_here,
            genesis: URL_SAFE_NO_PAD.encode(room.genesis().encode()),
        };
        if status.room != room.room_id() || status.author != binding.author.0 {
            return Err(unavailable());
        }
        binding.validate()?;
        Ok(binding)
    }
    pub(super) fn check(&self, room: &mut RoomSession) -> Result<()> {
        if &Self::capture(room)? != self {
            return Err(unavailable());
        }
        Ok(())
    }
    pub(super) fn genesis(&self) -> Result<PinnedGenesis> {
        if self.genesis.len() > MAX_GENESIS_BYTES * 2 {
            return Err(unavailable());
        }
        let bytes = URL_SAFE_NO_PAD
            .decode(&self.genesis)
            .map_err(|_| unavailable())?;
        if URL_SAFE_NO_PAD.encode(&bytes) != self.genesis {
            return Err(unavailable());
        }
        SignedGenesis::decode(&bytes)
            .and_then(|signed| signed.verify_pin(RoomId::from_bytes(self.room.0)))
            .map_err(|_| unavailable())
    }
    fn validate(&self) -> Result<()> {
        if [self.room, self.author, self.nonce]
            .iter()
            .any(|id| id.0 == [0; 32])
        {
            return Err(unavailable());
        }
        self.genesis()?;
        Ok(())
    }
}

/// JSON representation is local metadata, not the public network codec.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Snapshot {
    source: Hash,
    room: Hash,
    epoch: Hash,
    records: u64,
    bytes: u64,
    digest: [u8; 32],
}
impl From<Checkpoint> for Snapshot {
    fn from(value: Checkpoint) -> Self {
        Self {
            source: Hex(value.source),
            room: Hex(*value.room.as_bytes()),
            epoch: Hex(value.epoch),
            records: value.records,
            bytes: value.bytes,
            digest: value.digest,
        }
    }
}
impl From<Snapshot> for Checkpoint {
    fn from(value: Snapshot) -> Self {
        Self {
            source: value.source.0,
            room: RoomId::from_bytes(value.room.0),
            epoch: value.epoch.0,
            records: value.records,
            bytes: value.bytes,
            digest: value.digest,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Selected {
    pub(super) operation: Id,
    pub(super) source: network::Source,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Published {
    pub(super) operation: Id,
    pub(super) binding: Binding,
    pub(super) ready: Option<Snapshot>,
    pub(super) selected: BTreeMap<Hash, Selected>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    version: u32,
    account: Hash,
    source: Hash,
    events: u64,
    bytes: u64,
    slots: BTreeMap<Id, Published>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Event {
    Publish {
        operation: Id,
        slot: Id,
        binding: Binding,
    },
    Ready {
        slot: Id,
        backing: Snapshot,
    },
    Configure {
        operation: Id,
        slot: Id,
        source: network::Source,
    },
    Disable {
        operation: Id,
        slot: Id,
        peer: Hash,
    },
    Target {
        slot: Id,
        peer: Hash,
        selection: Id,
        target: Snapshot,
    },
}
impl Event {
    fn key(&self) -> [u8; 33] {
        match self {
            Self::Publish { operation, .. }
            | Self::Configure { operation, .. }
            | Self::Disable { operation, .. } => key(1, &operation.0),
            Self::Ready { slot, .. } => key(2, &slot.0),
            Self::Target { slot, peer, .. } => {
                let mut bytes = slot.0.to_vec();
                bytes.extend(peer.0);
                key(3, &bytes)
            }
        }
    }
    fn encode(&self) -> Result<Vec<u8>> {
        let bytes = serde_json::to_vec(self).map_err(|_| unavailable())?;
        if bytes.len() > disk::MAX_RECORD_BYTES {
            return Err(invalid());
        }
        Ok(bytes)
    }
    fn decode(entry: &Entry) -> Result<Self> {
        let event: Self = serde_json::from_slice(&entry.data).map_err(|_| unavailable())?;
        if event.key() != entry.key || event.encode()? != entry.data {
            return Err(unavailable());
        }
        Ok(event)
    }
}

fn digest(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"valhalla/headless/public-sync/v1\0");
    hash.update((domain.len() as u64).to_be_bytes());
    hash.update(domain);
    hash.update((bytes.len() as u64).to_be_bytes());
    hash.update(bytes);
    hash.finalize().into()
}
fn key(tag: u8, bytes: &[u8]) -> [u8; 33] {
    let mut key = [0; 33];
    key[0] = tag;
    key[1..].copy_from_slice(&digest(b"record", bytes));
    key
}
fn context(account: Hash, source: Hash) -> Result<StoreContext> {
    if account.0 == [0; 32] || source.0 == [0; 32] {
        return Err(invalid());
    }
    StoreContext::new(digest(b"namespace", &source.0), account.0).map_err(|_| invalid())
}

impl State {
    fn empty(account: Hash, source: Hash) -> Self {
        Self {
            version: VERSION,
            account,
            source,
            events: 0,
            bytes: 0,
            slots: BTreeMap::new(),
        }
    }
    fn apply(&mut self, event: &Event) -> Result<()> {
        match event {
            Event::Publish {
                operation,
                slot,
                binding,
            } => {
                valid_id(*operation)?;
                valid_id(*slot)?;
                binding.validate()?;
                if self.slots.contains_key(slot)
                    || self
                        .slots
                        .values()
                        .any(|old| old.binding.room == binding.room)
                {
                    return Err(conflict());
                }
                if self.slots.len() >= MAX_ROOMS {
                    return Err(capacity());
                }
                self.slots.insert(
                    *slot,
                    Published {
                        operation: *operation,
                        binding: binding.clone(),
                        ready: None,
                        selected: BTreeMap::new(),
                    },
                );
            }
            Event::Ready { slot, backing } => {
                let published = self.slots.get_mut(slot).ok_or_else(not_found)?;
                if published.ready.is_some() {
                    return Err(conflict());
                }
                Receiver::begin(
                    published.binding.genesis()?,
                    self.source.0,
                    self.source.0,
                    (*backing).into(),
                )
                .map_err(|_| unavailable())?;
                published.ready = Some(*backing);
            }
            Event::Configure {
                operation,
                slot,
                source,
            } => {
                valid_id(*operation)?;
                let peer = source_id(source)?;
                if peer == self.source {
                    return Err(invalid());
                }
                let published = self.slots.get_mut(slot).ok_or_else(not_found)?;
                if published.ready.is_none() {
                    return Err(unavailable());
                }
                if !published.selected.contains_key(&peer)
                    && published.selected.len() >= MAX_SOURCES
                {
                    return Err(capacity());
                }
                published.selected.insert(
                    peer,
                    Selected {
                        operation: *operation,
                        source: source.clone(),
                    },
                );
            }
            Event::Disable {
                operation,
                slot,
                peer,
            } => {
                valid_id(*operation)?;
                if peer.0 == [0; 32] {
                    return Err(invalid());
                }
                let published = self.slots.get_mut(slot).ok_or_else(not_found)?;
                if published.ready.is_none() {
                    return Err(unavailable());
                }
                published.selected.remove(peer);
            }
            Event::Target {
                slot,
                peer,
                selection,
                target,
            } => {
                let published = self.slots.get(slot).ok_or_else(not_found)?;
                let selected = published.selected.get(peer).ok_or_else(not_found)?;
                if selected.operation != *selection {
                    return Err(conflict());
                }
                Receiver::begin(
                    published.binding.genesis()?,
                    peer.0,
                    peer.0,
                    (*target).into(),
                )
                .map_err(|_| unavailable())?;
            }
        }
        self.events = self.events.checked_add(1).ok_or_else(capacity)?;
        self.bytes = self
            .bytes
            .checked_add(event.encode()?.len() as u64)
            .ok_or_else(capacity)?;
        Ok(())
    }
    fn encode(&self) -> Result<Vec<u8>> {
        if self.version != VERSION
            || self.account.0 == [0; 32]
            || self.source.0 == [0; 32]
            || self.slots.len() > MAX_ROOMS
            || self.events > LIMITS.max_records
            || self.bytes > LIMITS.max_record_bytes
        {
            return Err(unavailable());
        }
        let mut raw = MAGIC.to_vec();
        raw.extend(serde_json::to_vec(self).map_err(|_| unavailable())?);
        if raw.len() > IMAGE_LIMIT {
            return Err(capacity());
        }
        Ok(raw)
    }
}

pub(super) struct Metadata {
    store: Store,
    state: State,
    image: Vec<u8>,
    failed: bool,
}
impl Metadata {
    pub(super) fn create_new(path: &Path, account: Hash, source: Hash) -> Result<Self> {
        let state = State::empty(account, source);
        let image = state.encode()?;
        let mut store = Store::create_new(path, context(account, source)?, LIMITS)
            .map_err(|_| unavailable())?;
        store
            .publish(None, &image, &[])
            .map_err(|_| unavailable())?;
        let mut result = Self {
            store,
            state,
            image,
            failed: false,
        };
        result.check()?;
        Ok(result)
    }
    pub(super) fn open(path: &Path, account: Hash, source: Hash) -> Result<Self> {
        let mut store = Store::open(path, context(account, source)?).map_err(|_| unavailable())?;
        let image = store
            .load()
            .map_err(|_| unavailable())?
            .ok_or_else(unavailable)?;
        if !image.starts_with(MAGIC) || image.len() > IMAGE_LIMIT {
            return Err(unavailable());
        }
        let state: State =
            serde_json::from_slice(&image[MAGIC.len()..]).map_err(|_| unavailable())?;
        if state.account != account || state.source != source || state.encode()? != image {
            return Err(unavailable());
        }
        let mut result = Self {
            store,
            state,
            image,
            failed: false,
        };
        result.check()?;
        let mut expected = State::empty(account, source);
        while expected.events < result.state.events {
            let page = result
                .store
                .page(expected.events, 32)
                .map_err(|_| unavailable())?;
            if page.tip != result.state.events || page.records.is_empty() {
                return Err(unavailable());
            }
            for entry in page.records {
                if entry.cursor != expected.events + 1 {
                    return Err(unavailable());
                }
                expected
                    .apply(&Event::decode(&entry)?)
                    .map_err(|_| unavailable())?;
            }
        }
        if expected != result.state {
            return Err(unavailable());
        }
        Ok(result)
    }
    pub(super) fn check(&mut self) -> Result<()> {
        if self.failed {
            return Err(unavailable());
        }
        let result = (|| {
            if self.store.load().map_err(|_| unavailable())?.as_deref()
                != Some(self.image.as_slice())
            {
                return Err(unavailable());
            }
            let accounting = self.store.accounting().map_err(|_| unavailable())?;
            if accounting.records != self.state.events
                || accounting.tip != self.state.events
                || accounting.bytes != self.state.bytes
                || accounting.generation != self.state.events + 1
            {
                return Err(unavailable());
            }
            Ok(())
        })();
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    pub(super) fn accounting(&mut self) -> Result<disk::Accounting> {
        self.check()?;
        let result = self.store.accounting().map_err(|_| unavailable());
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    pub(super) fn ids(&self) -> impl Iterator<Item = Id> + '_ {
        self.state.slots.keys().copied()
    }
    pub(super) fn slot(&self, slot: Id) -> Result<&Published> {
        self.state.slots.get(&slot).ok_or_else(not_found)
    }
    pub(super) fn source(&self) -> Hash {
        self.state.source
    }
    /// An exact old operation is acknowledged without applying it to today's image.
    pub(super) fn reserve(&mut self, event: Event) -> Result<bool> {
        self.check()?;
        let raw = event.encode()?;
        let retained = self.store.read(event.key()).map_err(|_| {
            self.failed = true;
            unavailable()
        })?;
        if let Some(retained) = retained {
            return if retained == raw {
                Ok(false)
            } else {
                Err(conflict())
            };
        }
        let mut next = self.state.clone();
        next.apply(&event)?;
        let accounting = self.store.accounting().map_err(|_| {
            self.failed = true;
            unavailable()
        })?;
        if next.events > LIMITS.max_records.min(accounting.limits.max_records)
            || next.bytes
                > LIMITS
                    .max_record_bytes
                    .min(accounting.limits.max_record_bytes)
        {
            return Err(capacity());
        }
        let image = next.encode()?;
        let record = Record::new(event.key(), &raw).map_err(|_| invalid())?;
        if let Err(error) = self.store.publish(Some(&self.image), &image, &[record]) {
            match error {
                disk::Error::Conflict | disk::Error::Refused => {
                    // These store failures roll back. Keep an intact metadata
                    // image usable, including exact old-operation receipts.
                    self.check()?;
                    return Err(if error == disk::Error::Conflict {
                        conflict()
                    } else {
                        capacity()
                    });
                }
                _ => {
                    self.failed = true;
                    return Err(unavailable());
                }
            }
        }
        self.state = next;
        self.image = image;
        self.check()?;
        Ok(true)
    }
    pub(super) fn initial_target(&mut self, slot: Id, peer: Hash) -> Result<Option<Checkpoint>> {
        self.check()?;
        let mut id = slot.0.to_vec();
        id.extend(peer.0);
        let record_key = key(3, &id);
        let result = (|| {
            let Some(raw) = self.store.read(record_key).map_err(|_| unavailable())? else {
                return Ok(None);
            };
            let event = Event::decode(&Entry {
                cursor: 0,
                key: record_key,
                data: raw,
            })?;
            match event {
                Event::Target {
                    slot: retained_slot,
                    peer: retained_peer,
                    target,
                    ..
                } if retained_slot == slot && retained_peer == peer => Ok(Some(target.into())),
                _ => Err(unavailable()),
            }
        })();
        if result.is_err() {
            self.failed = true;
        }
        result
    }
}
