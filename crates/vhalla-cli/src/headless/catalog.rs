//! Durable local room locators and consumed grant authorizations.
//!
//! Room controllers authenticate their own state. A catalog locator is not room
//! authority, and a grant receipt is never sufficient to reconstruct a budget.

use serde::{de::Error as _, Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest as _, Sha256};
use std::{fmt, path::Path};
use vhalla_direct_store::{Accounting, Context, Error, Limits, Record, Store};

pub(super) const MAX_ROOMS: usize = 64;
const VERSION: u32 = 1;
const MAGIC: &[u8; 8] = b"VHDCAT01";
const MAX_IMAGE: usize = 128 * 1024;
const INITIAL_LIMITS: Limits = Limits {
    max_records: 100_000,
    max_record_bytes: 32 * 1024 * 1024,
};

/// Canonical full nonzero identifiers. Labels and prefixes are never locators.
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
pub(super) struct Hex<const N: usize>(pub(super) [u8; N]);
pub(super) type Id = Hex<16>;
pub(super) type Hash = Hex<32>;

impl<const N: usize> Hex<N> {
    pub(super) fn parse(value: &str) -> Result<Self, Error> {
        if value.len() != N * 2 {
            return Err(Error::Refused);
        }
        fn digit(byte: u8) -> Result<u8, Error> {
            match byte {
                b'0'..=b'9' => Ok(byte - b'0'),
                b'a'..=b'f' => Ok(byte - b'a' + 10),
                _ => Err(Error::Refused),
            }
        }
        let mut bytes = [0; N];
        for (result, pair) in bytes
            .iter_mut()
            .zip(value.as_bytes().as_chunks::<2>().0.iter())
        {
            *result = digit(pair[0])? * 16 + digit(pair[1])?;
        }
        if bytes == [0; N] {
            return Err(Error::Refused);
        }
        Ok(Self(bytes))
    }
}

impl<const N: usize> fmt::Display for Hex<N> {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(output, "{byte:02x}")?;
        }
        Ok(())
    }
}
impl<const N: usize> fmt::Debug for Hex<N> {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, output)
    }
}
impl<const N: usize> Serialize for Hex<N> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}
impl<'de, const N: usize> Deserialize<'de> for Hex<N> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value)
            .map_err(|_| D::Error::custom("expected a full nonzero lowercase hex ID"))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Kind {
    Public,
    Private,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Locator {
    Public {
        pin: Hash,
    },
    Private {
        room: Hash,
        anchor: Hash,
        account: Hash,
        device: Hash,
    },
}

impl Locator {
    fn valid_for(self, expected_account: Hash) -> bool {
        match self {
            Self::Public { pin } => pin.0 != [0; 32],
            Self::Private {
                room,
                anchor,
                account,
                device,
            } => {
                account == expected_account
                    && [room, anchor, account, device]
                        .iter()
                        .all(|field| field.0 != [0; 32])
            }
        }
    }

    pub(super) fn kind(self) -> Kind {
        match self {
            Self::Public { .. } => Kind::Public,
            Self::Private { .. } => Kind::Private,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Slot {
    pub(super) id: Id,
    pub(super) kind: Kind,
    pub(super) intent: Hash,
    /// Fresh local provenance retained before creating keys. Public owners also
    /// sign it into genesis; public joins retain it without changing genesis.
    pub(super) creation_nonce: Hash,
    pub(super) locator: Option<Locator>,
    pub(super) ready: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    version: u32,
    account: Hash,
    slots: Vec<Slot>,
    grant_claims: u64,
}

pub(super) struct Catalog {
    store: Store,
    image: Vec<u8>,
    state: State,
    failed: bool,
}

pub(super) fn commitment(domain: &[u8], bytes: &[u8]) -> Hash {
    let mut hash = Sha256::new();
    hash.update(b"valhalla/headless/catalog/v1\0");
    hash.update((domain.len() as u64).to_be_bytes());
    hash.update(domain);
    hash.update((bytes.len() as u64).to_be_bytes());
    hash.update(bytes);
    Hex(hash.finalize().into())
}

fn context(account: Hash) -> Result<Context, Error> {
    Context::new(commitment(b"namespace", &[]).0, account.0)
}

fn key(kind: u8, id: Id) -> [u8; 33] {
    let mut key = [0; 33];
    key[0] = kind;
    key[1..].copy_from_slice(&commitment(b"record-key", &id.0).0);
    key
}

fn encode(state: &State) -> Result<Vec<u8>, Error> {
    check_state(state)?;
    let mut raw = MAGIC.to_vec();
    raw.extend(serde_json::to_vec(state).map_err(|_| Error::Corrupt)?);
    if raw.len() > MAX_IMAGE {
        return Err(Error::Refused);
    }
    Ok(raw)
}

fn check_state(state: &State) -> Result<(), Error> {
    if state.version != VERSION
        || state.account.0 == [0; 32]
        || state.slots.len() > MAX_ROOMS
        || state.grant_claims > 1_000_000
    {
        return Err(Error::Corrupt);
    }
    for (index, slot) in state.slots.iter().enumerate() {
        if slot.id.0 == [0; 16]
            || slot.intent.0 == [0; 32]
            || slot.creation_nonce.0 == [0; 32]
            || state.slots[..index].iter().any(|earlier| {
                earlier.id == slot.id || earlier.creation_nonce == slot.creation_nonce
            })
            || (slot.ready && slot.locator.is_none())
            || slot
                .locator
                .is_some_and(|locator| locator.kind() != slot.kind)
            || slot
                .locator
                .is_some_and(|locator| !locator.valid_for(state.account))
        {
            return Err(Error::Corrupt);
        }
    }
    Ok(())
}

impl Catalog {
    pub(super) fn create_new(path: &Path, account: Hash) -> Result<Self, Error> {
        let state = State {
            version: VERSION,
            account,
            slots: Vec::new(),
            grant_claims: 0,
        };
        let image = encode(&state)?;
        let mut store = Store::create_new(path, context(account)?, INITIAL_LIMITS)?;
        store.publish(None, &image, &[])?;
        Ok(Self {
            store,
            image,
            state,
            failed: false,
        })
    }

    pub(super) fn open(path: &Path, account: Hash) -> Result<Self, Error> {
        let mut store = Store::open(path, context(account)?)?;
        let image = store.load()?.ok_or(Error::Corrupt)?;
        if image.len() > MAX_IMAGE || !image.starts_with(MAGIC) {
            return Err(Error::Corrupt);
        }
        let state: State =
            serde_json::from_slice(&image[MAGIC.len()..]).map_err(|_| Error::Corrupt)?;
        if state.account != account || encode(&state)? != image {
            return Err(Error::Corrupt);
        }
        let mut catalog = Self {
            store,
            image,
            state,
            failed: false,
        };
        catalog.check_records()?;
        Ok(catalog)
    }

    /// Refuse changed state on this handle; only explicit open may recover.
    pub(super) fn check(&mut self) -> Result<(), Error> {
        if self.failed {
            return Err(Error::Uncertain);
        }
        let loaded = self.store.load().inspect_err(|_| self.failed = true)?;
        if loaded.as_deref() != Some(self.image.as_slice()) {
            self.failed = true;
            return Err(Error::Corrupt);
        }
        Ok(())
    }

    pub(super) fn slots(&self) -> &[Slot] {
        &self.state.slots
    }
    pub(super) fn slot(&self, id: Id) -> Option<&Slot> {
        self.state.slots.iter().find(|slot| slot.id == id)
    }
    /// Recover create-versus-join from the immutable initial public reservation.
    /// A later locator binding never turns an owner creation into a join.
    pub(super) fn public_creation_mode(&mut self, id: Id) -> Result<bool, Error> {
        self.check()?;
        let current = self.slot(id).cloned().ok_or(Error::Refused)?;
        if current.kind != Kind::Public {
            return Err(Error::Refused);
        }
        let result = (|| {
            let raw = self.store.read(key(1, id))?.ok_or(Error::Corrupt)?;
            let initial: Slot = serde_json::from_slice(&raw).map_err(|_| Error::Corrupt)?;
            if initial.id != current.id
                || initial.kind != current.kind
                || initial.intent != current.intent
                || initial.creation_nonce != current.creation_nonce
                || initial.creation_nonce.0 == [0; 32]
                || initial.ready
            {
                return Err(Error::Corrupt);
            }
            let bound = self.store.read(key(2, id))?;
            match (initial.locator, current.locator) {
                (Some(original), Some(current))
                    if original == current
                        && original.kind() == Kind::Public
                        && original.valid_for(self.state.account)
                        && bound.is_none() => {}
                (None, Some(current)) if current.kind() == Kind::Public => {
                    let retained: Locator =
                        serde_json::from_slice(bound.as_deref().ok_or(Error::Corrupt)?)
                            .map_err(|_| Error::Corrupt)?;
                    if retained != current || !retained.valid_for(self.state.account) {
                        return Err(Error::Corrupt);
                    }
                }
                (None, None) if bound.is_none() => {}
                _ => return Err(Error::Corrupt),
            }
            let completion = self.store.read(key(3, id))?;
            if completion.as_deref() != current.ready.then_some(current.id.0.as_slice()) {
                return Err(Error::Corrupt);
            }
            Ok(initial.locator.is_none())
        })();
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    pub(super) fn grant_claims(&self) -> u64 {
        self.state.grant_claims
    }
    pub(super) fn accounting(&mut self) -> Result<Accounting, Error> {
        self.check()?;
        self.store.accounting()
    }
    pub(super) fn expand_limits(&mut self, limits: Limits) -> Result<Accounting, Error> {
        self.check()?;
        self.store.expand_limits(limits)
    }

    /// True authorizes this invocation to attempt creation once. False means
    /// inspect/reopen the reserved slot; never run a creator again there.
    pub(super) fn reserve(
        &mut self,
        id: Id,
        kind: Kind,
        intent: Hash,
        locator: Option<Locator>,
    ) -> Result<bool, Error> {
        self.check()?;
        if id.0 == [0; 16]
            || intent.0 == [0; 32]
            || locator
                .is_some_and(|value| value.kind() != kind || !value.valid_for(self.state.account))
        {
            return Err(Error::Refused);
        }
        if let Some(slot) = self.slot(id) {
            if slot.kind != kind
                || slot.intent != intent
                || locator.is_some_and(|value| slot.locator != Some(value))
            {
                return Err(Error::Conflict);
            }
            return Ok(false);
        }
        if self.state.slots.len() == MAX_ROOMS {
            return Err(Error::Refused);
        }
        let mut creation_nonce = [0; 32];
        getrandom::fill(&mut creation_nonce).map_err(|_| Error::Refused)?;
        if creation_nonce == [0; 32] {
            return Err(Error::Refused);
        }
        let slot = Slot {
            id,
            kind,
            intent,
            creation_nonce: Hex(creation_nonce),
            locator,
            ready: false,
        };
        let record = Record::new(
            key(1, id),
            &serde_json::to_vec(&slot).map_err(|_| Error::Corrupt)?,
        )?;
        let mut next = self.state.clone();
        next.slots.push(slot);
        self.publish(next, &[record])?;
        Ok(true)
    }

    /// Bind a previously missing locator exactly once. The caller must verify
    /// native room authority; a recovered marker alone is insufficient.
    pub(super) fn bind(&mut self, id: Id, locator: Locator) -> Result<(), Error> {
        self.check()?;
        if !locator.valid_for(self.state.account) {
            return Err(Error::Refused);
        }
        let slot = self.slot(id).ok_or(Error::Refused)?;
        if let Some(existing) = slot.locator {
            return if existing == locator {
                Ok(())
            } else {
                Err(Error::Conflict)
            };
        }
        if slot.kind != locator.kind() {
            return Err(Error::Conflict);
        }
        let record = Record::new(
            key(2, id),
            &serde_json::to_vec(&locator).map_err(|_| Error::Corrupt)?,
        )?;
        let mut next = self.state.clone();
        next.slots
            .iter_mut()
            .find(|slot| slot.id == id)
            .ok_or(Error::Corrupt)?
            .locator = Some(locator);
        self.publish(next, &[record])
    }

    pub(super) fn complete(&mut self, id: Id) -> Result<(), Error> {
        self.check()?;
        let slot = self.slot(id).ok_or(Error::Refused)?;
        if slot.ready {
            return Ok(());
        }
        if slot.locator.is_none() {
            return Err(Error::Refused);
        }
        let record = Record::new(key(3, id), &id.0)?;
        let mut next = self.state.clone();
        next.slots
            .iter_mut()
            .find(|slot| slot.id == id)
            .ok_or(Error::Corrupt)?
            .ready = true;
        self.publish(next, &[record])
    }

    /// Consume a complete authorization before returning any live token.
    /// False is an existing claim, never permission to restore its initial budget.
    pub(super) fn claim_grant(&mut self, operation: Id, intent: Hash) -> Result<bool, Error> {
        self.check()?;
        if operation.0 == [0; 16] || intent.0 == [0; 32] {
            return Err(Error::Refused);
        }
        if let Some(old) = self.store.read(key(4, operation))? {
            return if old == intent.0 {
                Ok(false)
            } else {
                Err(Error::Conflict)
            };
        }
        let record = Record::new(key(4, operation), &intent.0)?;
        let mut next = self.state.clone();
        next.grant_claims = next.grant_claims.checked_add(1).ok_or(Error::Refused)?;
        self.publish(next, &[record])?;
        Ok(true)
    }

    fn publish(&mut self, state: State, records: &[Record]) -> Result<(), Error> {
        let image = encode(&state)?;
        self.store
            .publish(Some(&self.image), &image, records)
            .inspect_err(|error| {
                if *error != Error::Refused {
                    self.failed = true;
                }
            })?;
        self.image = image;
        self.state = state;
        Ok(())
    }

    fn check_records(&mut self) -> Result<(), Error> {
        // Check every image reference against immutable intent/completion data.
        // Grant records need no in-memory registry; replay only counts them.
        let mut expected_records = self.state.grant_claims;
        for slot in &self.state.slots {
            let raw = self.store.read(key(1, slot.id))?.ok_or(Error::Corrupt)?;
            let intent: Slot = serde_json::from_slice(&raw).map_err(|_| Error::Corrupt)?;
            if intent.id != slot.id
                || intent.kind != slot.kind
                || intent.intent != slot.intent
                || intent.creation_nonce != slot.creation_nonce
                || intent.ready
            {
                return Err(Error::Corrupt);
            }
            expected_records += 1;
            if intent.locator != slot.locator {
                if intent.locator.is_some() {
                    return Err(Error::Corrupt);
                }
                let bound = self.store.read(key(2, slot.id))?.ok_or(Error::Corrupt)?;
                let locator: Locator =
                    serde_json::from_slice(&bound).map_err(|_| Error::Corrupt)?;
                if Some(locator) != slot.locator {
                    return Err(Error::Corrupt);
                }
                expected_records += 1;
            }
            if slot.ready {
                if self.store.read(key(3, slot.id))?.as_deref() != Some(&slot.id.0) {
                    return Err(Error::Corrupt);
                }
                expected_records += 1;
            }
        }
        let mut after = 0;
        let mut claims = 0;
        loop {
            let page = self.store.page(after, 32)?;
            if page.tip != expected_records {
                return Err(Error::Corrupt);
            }
            for record in &page.records {
                if !(1..=4).contains(&record.key[0]) {
                    return Err(Error::Corrupt);
                }
                if record.key[0] == 4 {
                    if record.data.len() != 32 || record.data == [0; 32] {
                        return Err(Error::Corrupt);
                    }
                    claims += 1;
                }
            }
            match page.next {
                Some(next) => after = next,
                None => break,
            }
        }
        if claims != self.state.grant_claims {
            return Err(Error::Corrupt);
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "catalog_tests.rs"]
mod tests;
