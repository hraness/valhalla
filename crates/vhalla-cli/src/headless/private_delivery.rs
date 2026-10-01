//! Durable, explicit selection of existing private delivery profiles.
//!
//! The manager never initializes a profile or queue, creates an agent grant,
//! signs application messages, resumes stopped attempts, or enables Watch.
//! Immutable selection history survives detach and host replacement.

use super::catalog::{Hash, Hex, Id, MAX_ROOMS};
use crate::private_rooms::agent_delivery::{Driver, RoomTickError};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::File,
    io::Read,
    path::{Component, Path, PathBuf},
    time::{Duration, Instant},
};
use vhalla_custody::{self as custody, Owner};
use vhalla_direct_store::{self as disk, Record, Store};
use vhalla_private_kernel::{
    protocol::{AnchorId, Key, PrivateRoomScope, RoomId},
    Context,
};
use vhalla_private_native::{
    client::RoomSession,
    relay::{
        delivery::{JobState, JobStatus},
        net::NetError,
    },
};

const IMAGE: &[u8; 8] = b"VHDPM001";
const INTENT: &[u8; 8] = b"VHDPI001";
const PROFILE_BYTES: usize = 16_384;
const PATH_BYTES: usize = 4096;
const PAGE: usize = 16;
const LIMITS: disk::Limits = disk::Limits {
    max_records: 100_000,
    max_record_bytes: 32 * 1024 * 1024,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Error {
    Invalid,
    Conflict,
    NotFound,
    Capacity,
    StaleProfile,
    Refused,
    NativeUnavailable,
    RoomMismatch,
    Store(disk::Error),
}
type Result<T> = std::result::Result<T, Error>;
impl From<disk::Error> for Error {
    fn from(value: disk::Error) -> Self {
        Self::Store(value)
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(output, "{self:?}")
    }
}
impl std::error::Error for Error {}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Profile {
    path: PathBuf,
    hash: Hash,
}
#[derive(Clone, Debug, Eq, PartialEq)]
enum Action {
    Attach(Profile),
    Detach,
}
#[derive(Clone, Debug, Eq, PartialEq)]
struct Intent {
    operation: Id,
    slot: Id,
    context: Context,
    action: Action,
}
#[derive(Clone, Debug, Eq, PartialEq)]
struct Selected {
    context: Context,
    active: Option<Id>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
struct State {
    account: Hash,
    operations: u64,
    bytes: u64,
    slots: BTreeMap<Id, Selected>,
}

struct ProfileGuard {
    path: PathBuf,
    parent: File,
    file: File,
    owner: Owner,
    hash: Hash,
}
impl ProfileGuard {
    fn open(profile: &Profile) -> Result<Self> {
        path_bytes(&profile.path)?;
        if profile.hash.0 == [0; 32]
            || profile
                .path
                .canonicalize()
                .map_err(|_| Error::StaleProfile)?
                .as_os_str()
                != profile.path.as_os_str()
        {
            return Err(Error::StaleProfile);
        }
        let (parent, owner) =
            custody::open_private_directory(profile.path.parent().ok_or(Error::Invalid)?)
                .map_err(|_| Error::StaleProfile)?;
        if owner != Owner::current().map_err(|_| Error::StaleProfile)? {
            return Err(Error::StaleProfile);
        }
        let file = custody::open_private_file(&profile.path, owner, PROFILE_BYTES)
            .map_err(|_| Error::StaleProfile)?;
        let guard = Self {
            path: profile.path.clone(),
            parent,
            file,
            owner,
            hash: profile.hash,
        };
        guard.check()?;
        Ok(guard)
    }
    fn check(&self) -> Result<()> {
        if self
            .path
            .canonicalize()
            .map_err(|_| Error::StaleProfile)?
            .as_os_str()
            != self.path.as_os_str()
        {
            return Err(Error::StaleProfile);
        }
        let (parent, owner) =
            custody::open_private_directory(self.path.parent().ok_or(Error::StaleProfile)?)
                .map_err(|_| Error::StaleProfile)?;
        let mut file = custody::open_private_file(&self.path, owner, PROFILE_BYTES)
            .map_err(|_| Error::StaleProfile)?;
        if owner != self.owner
            || owner != Owner::current().map_err(|_| Error::StaleProfile)?
            || !custody::same_open_file(&parent, &self.parent).map_err(|_| Error::StaleProfile)?
            || !custody::same_open_file(&file, &self.file).map_err(|_| Error::StaleProfile)?
        {
            return Err(Error::StaleProfile);
        }
        let mut bytes = zeroize::Zeroizing::new(Vec::new());
        (&mut file)
            .take((PROFILE_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| Error::StaleProfile)?;
        if bytes.is_empty()
            || bytes.len() > PROFILE_BYTES
            || <[u8; 32]>::from(Sha256::digest(bytes.as_slice())) != self.hash.0
        {
            return Err(Error::StaleProfile);
        }
        let current = custody::open_private_file(&self.path, owner, PROFILE_BYTES)
            .map_err(|_| Error::StaleProfile)?;
        if !custody::same_open_file(&current, &self.file).map_err(|_| Error::StaleProfile)? {
            return Err(Error::StaleProfile);
        }
        Ok(())
    }
}

struct Live {
    // Join the finite relay worker before releasing profile custody.
    driver: Driver,
    guard: ProfileGuard,
}
impl Live {
    fn open(profile: &Profile, context: Context) -> Result<Self> {
        let guard = ProfileGuard::open(profile)?;
        let driver = Driver::open_polling_bound(&profile.path, context, profile.hash.0)
            .map_err(|_| Error::Refused)?;
        let live = Self { driver, guard };
        live.check()?;
        Ok(live)
    }
    fn check(&self) -> Result<()> {
        self.guard.check()?;
        self.driver
            .check_bound_profile(&self.guard.path, self.guard.hash.0)
            .map_err(|_| Error::StaleProfile)
    }
}
struct Runtime {
    profile: Profile,
    live: Option<Live>,
    failure: Option<Error>,
    // Diagnostics belong to this exact selection, including after a failed
    // driver is dropped. Reopen/reselection constructs a fresh observation.
    transport_status: Value,
}
impl Runtime {
    fn open(profile: Profile, context: Context) -> Self {
        match Live::open(&profile, context) {
            Ok(live) => Self {
                profile,
                transport_status: live.driver.transport_status(),
                live: Some(live),
                failure: None,
            },
            Err(error) => Self {
                profile,
                live: None,
                failure: Some(error),
                transport_status: Value::Null,
            },
        }
    }
    fn fail(&mut self, error: Error) {
        if let Some(live) = &self.live {
            self.transport_status = live.driver.transport_status();
        }
        self.live = None;
        self.failure = Some(error);
    }
}

pub(super) struct Manager {
    // The owning service must drop this manager before its native room handles.
    running: BTreeMap<Id, Runtime>,
    store: Store,
    state: State,
    image: Vec<u8>,
    poisoned: bool,
    #[cfg(test)]
    pause_tick: bool,
}

impl Manager {
    /// The caller retains exclusive service custody for this value's lifetime.
    pub(super) fn initialize(path: &Path, account: Hash) -> Result<Self> {
        let state = State {
            account,
            operations: 0,
            bytes: 0,
            slots: BTreeMap::new(),
        };
        let image = encode_state(&state)?;
        let mut store = Store::create_new(path, store_context(account)?, LIMITS)?;
        store.publish(None, &image, &[])?;
        check_store(&mut store, &state, &image)?;
        Ok(Self {
            running: BTreeMap::new(),
            store,
            state,
            image,
            poisoned: false,
            #[cfg(test)]
            pause_tick: false,
        })
    }

    /// Existing selections and queues only. A failed room profile does not
    /// prevent another room from opening; selection history is never repaired.
    pub(super) fn open(path: &Path, account: Hash) -> Result<Self> {
        let mut store = Store::open(path, store_context(account)?)?;
        let image = store.load()?.ok_or(Error::Store(disk::Error::Corrupt))?;
        let state = decode_state(&image)?;
        if state.account != account {
            return Err(Error::Store(disk::Error::Corrupt));
        }
        check_store(&mut store, &state, &image)?;
        let mut replay = State {
            account,
            operations: 0,
            bytes: 0,
            slots: BTreeMap::new(),
        };
        let mut after = 0;
        while after < state.operations {
            let page = store.page(after, disk::MAX_PAGE_RECORDS)?;
            if page.tip != state.operations || page.records.is_empty() {
                return Err(Error::Store(disk::Error::Corrupt));
            }
            for entry in page.records {
                let intent = decode_intent(&entry.data)?;
                if entry.cursor != after + 1 || entry.key != record_key(intent.operation) {
                    return Err(Error::Store(disk::Error::Corrupt));
                }
                apply(&mut replay, &intent, entry.data.len())
                    .map_err(|_| Error::Store(disk::Error::Corrupt))?;
                after = entry.cursor;
            }
        }
        if replay != state {
            return Err(Error::Store(disk::Error::Corrupt));
        }
        let mut manager = Self {
            running: BTreeMap::new(),
            store,
            state,
            image,
            poisoned: false,
            #[cfg(test)]
            pause_tick: false,
        };
        let selected: Vec<_> = manager
            .state
            .slots
            .iter()
            .filter_map(|(slot, selected)| {
                selected
                    .active
                    .map(|operation| (*slot, selected.context, operation))
            })
            .collect();
        for (slot, context, operation) in selected {
            let intent = manager
                .retained(operation)?
                .ok_or(Error::Store(disk::Error::Corrupt))?;
            let Action::Attach(profile) = intent.action else {
                return Err(Error::Store(disk::Error::Corrupt));
            };
            if intent.slot != slot || intent.context != context {
                return Err(Error::Store(disk::Error::Corrupt));
            }
            manager
                .running
                .insert(slot, Runtime::open(profile, context));
        }
        manager.check()?;
        Ok(manager)
    }

    /// Explicit host choice. A replacement profile must already own initialized
    /// queues, and the caller supplies the independently selected byte digest.
    pub(super) fn attach(
        &mut self,
        operation: Id,
        slot: Id,
        context: Context,
        path: PathBuf,
        expected_hash: Hash,
    ) -> Result<Value> {
        let intent = Intent {
            operation,
            slot,
            context,
            action: Action::Attach(Profile {
                path,
                hash: expected_hash,
            }),
        };
        let record = self.prepare(&intent)?;
        if record.is_none() {
            return self.ack(slot, operation, true);
        }
        let Action::Attach(profile) = &intent.action else {
            unreachable!()
        };
        let reuse = self
            .running
            .get(&slot)
            .is_some_and(|runtime| runtime.profile == *profile && runtime.live.is_some());
        let candidate = if reuse {
            let result = self
                .running
                .get(&slot)
                .and_then(|runtime| runtime.live.as_ref())
                .ok_or(Error::Refused)?
                .check();
            if let Err(error) = result {
                self.running
                    .get_mut(&slot)
                    .ok_or(Error::Refused)?
                    .fail(error);
                return Err(error);
            }
            None
        } else {
            Some(Live::open(profile, context)?)
        };
        self.publish(&intent, record.ok_or(Error::Invalid)?)?;
        if let Some(live) = candidate {
            self.running.insert(
                slot,
                Runtime {
                    profile: profile.clone(),
                    transport_status: live.driver.transport_status(),
                    live: Some(live),
                    failure: None,
                },
            );
        } else if reuse {
            let runtime = self.running.get_mut(&slot).ok_or(Error::Refused)?;
            let live = runtime.live.as_mut().ok_or(Error::Refused)?;
            live.driver.clear_transport_observation();
            runtime.transport_status = live.driver.transport_status();
        }
        self.ack(slot, operation, false)
    }

    /// Retain a durable stop selection. Neither old profile files nor any queue,
    /// staged ciphertext, retry evidence or kernel state is deleted.
    pub(super) fn detach(&mut self, operation: Id, slot: Id, context: Context) -> Result<Value> {
        let intent = Intent {
            operation,
            slot,
            context,
            action: Action::Detach,
        };
        let Some(record) = self.prepare(&intent)? else {
            return self.ack(slot, operation, true);
        };
        self.publish(&intent, record)?;
        self.running.remove(&slot);
        self.ack(slot, operation, false)
    }

    pub(super) fn active_rooms(&self) -> Vec<Id> {
        self.state
            .slots
            .iter()
            .filter_map(|(id, selected)| selected.active.map(|_| *id))
            .collect()
    }

    /// The actor awaits accepted work to completion; the driver's deadline
    /// limits work cooperatively and never cancels an uncertain native write.
    pub(super) async fn tick_room(&mut self, slot: Id, room: &mut RoomSession) -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(2);
        self.check()?;
        let selected = self.state.slots.get(&slot).ok_or(Error::NotFound)?;
        if selected.active.is_none() {
            return Err(Error::NotFound);
        }
        let context = match room.status() {
            Ok(status) => status.context,
            Err(_) => {
                if let Some(runtime) = self.running.get_mut(&slot) {
                    runtime.fail(Error::NativeUnavailable);
                }
                return Err(Error::NativeUnavailable);
            }
        };
        if context != selected.context {
            return Err(Error::RoomMismatch);
        }
        let runtime = self.running.get_mut(&slot).ok_or(Error::Refused)?;
        let Some(mut live) = runtime.live.take() else {
            return Err(runtime.failure.unwrap_or(Error::Refused));
        };
        // Dropping a cancelled tick drops this owned driver. A subsequent tick
        // cannot silently reopen it or repeat an uncertain delivery stage.
        runtime.failure = Some(Error::Refused);
        #[cfg(test)]
        if self.pause_tick {
            std::future::pending::<()>().await;
        }
        if let Err(error) = live.check() {
            runtime.failure = Some(error);
            return Err(error);
        }
        let result = live.driver.tick_room(room, deadline).await;
        // A valid relay reply is transport evidence even if later native or
        // profile checks fence this tick. It is never recipient acceptance.
        let transport_status = live.driver.transport_status();
        let profile_check = live.check();
        let manager_check = self.check();
        if let Some(runtime) = self.running.get_mut(&slot) {
            runtime.transport_status = transport_status;
        }
        // Native uncertainty/authentication failures must not be hidden by a
        // simultaneous profile drift, queue capacity, or manager-store failure.
        if result == Err(RoomTickError::NativeUnavailable) || room.status().is_err() {
            if let Some(runtime) = self.running.get_mut(&slot) {
                runtime.fail(Error::NativeUnavailable);
            }
            return Err(Error::NativeUnavailable);
        }
        manager_check?;
        let runtime = self.running.get_mut(&slot).ok_or(Error::Refused)?;
        if let Err(error) = profile_check {
            runtime.failure = Some(error);
            return Err(error);
        }
        if result.is_err() {
            let full = [false, true].into_iter().any(|controls| {
                live.driver.queue_capacity(controls).is_ok_and(
                    |(jobs, max_jobs, bytes, max_bytes)| jobs >= max_jobs || bytes >= max_bytes,
                )
            });
            let error = if full {
                Error::Capacity
            } else {
                Error::Refused
            };
            runtime.failure = Some(error);
            return Err(error);
        }
        runtime.live = Some(live);
        runtime.failure = None;
        Ok(())
    }

    /// End live drivers without changing the durable operator selection.
    pub(super) fn invalidate(&mut self) {
        for runtime in self.running.values_mut() {
            runtime.fail(Error::Refused);
        }
    }

    pub(super) fn close_room(&mut self, slot: Id) {
        if let Some(runtime) = self.running.get_mut(&slot) {
            if let Some(live) = &runtime.live {
                runtime.transport_status = live.driver.transport_status();
            }
            runtime.live = None;
            runtime.failure.get_or_insert(Error::Refused);
        }
    }

    /// Trusted administration only: paths and profile hashes never enter agent
    /// tools. Queue retention is reported separately from recipient acceptance.
    pub(super) fn status(&mut self, slot: Id, after: u64, limit: usize) -> Result<Value> {
        self.check()?;
        if limit == 0 || limit > PAGE {
            return Err(Error::Invalid);
        }
        let selected = self.state.slots.get(&slot).ok_or(Error::NotFound)?;
        let operation = selected.active;
        let context = context_json(selected.context);
        let mut report = json!({"room":slot,"context":context,"selection_operation":operation,"state":"detached","relay_retention":"reported by each queue job only","recipient_acceptance":"not inferred from relay retention; inspect authenticated native kernel receipts",
            "transport":null,"last_transport_observation":null,
            "transport_observation_scope":"last successful validated relay reply; path snapshots, not byte accounting"});
        if let Some(runtime) = self.running.get_mut(&slot) {
            report["profile"] = json!(runtime.profile.path);
            report["profile_hash"] = json!(runtime.profile.hash);
            if let Some(live) = &runtime.live {
                let inspected = (|| {
                    live.check()?;
                    let normal = live
                        .driver
                        .outbox_jobs(after, limit)
                        .map_err(|_| Error::Refused)?;
                    let controls = live
                        .driver
                        .control_jobs(after, limit)
                        .map_err(|_| Error::Refused)?;
                    let normal_capacity = live
                        .driver
                        .queue_capacity(false)
                        .map_err(|_| Error::Refused)?;
                    let control_capacity = live
                        .driver
                        .queue_capacity(true)
                        .map_err(|_| Error::Refused)?;
                    let transport_status = live.driver.transport_status();
                    live.check()?;
                    Ok((
                        normal,
                        controls,
                        normal_capacity,
                        control_capacity,
                        transport_status,
                    ))
                })();
                match inspected {
                    Ok((normal, controls, normal_capacity, control_capacity, transport_status)) => {
                        report["application"] = queue_json(&normal, normal_capacity);
                        report["controls"] = queue_json(&controls, control_capacity);
                        runtime.transport_status = transport_status;
                    }
                    Err(error) => runtime.fail(error),
                }
            }
            report["transport"] = runtime.transport_status["transport"].clone();
            report["last_transport_observation"] =
                runtime.transport_status["last_transport_observation"].clone();
            report["state"] = json!(match runtime.failure {
                None => "active",
                Some(Error::StaleProfile) => "stale_profile",
                Some(Error::Capacity) => "capacity",
                Some(Error::NativeUnavailable) => "native_unavailable",
                Some(_) => "refused",
            });
        } else if operation.is_some() {
            return Err(Error::Store(disk::Error::Corrupt));
        }
        self.check()?;
        Ok(report)
    }

    fn ack(&mut self, slot: Id, operation: Id, exact_retry: bool) -> Result<Value> {
        Ok(
            json!({"operation":operation,"exact_retry":exact_retry,"current":self.status(slot,0,PAGE)?}),
        )
    }
    fn prepare(&mut self, intent: &Intent) -> Result<Option<Record>> {
        self.check()?;
        let bytes = encode_intent(intent)?;
        if let Some(retained) = self.retained(intent.operation)? {
            return if retained == *intent {
                Ok(None)
            } else {
                Err(Error::Conflict)
            };
        }
        let mut next = self.state.clone();
        apply(&mut next, intent, bytes.len())?;
        let accounting = match self.store.accounting() {
            Ok(value) => value,
            Err(error) => {
                self.poisoned = true;
                self.invalidate();
                return Err(error.into());
            }
        };
        if next.operations > accounting.limits.max_records
            || next.bytes > accounting.limits.max_record_bytes
        {
            return Err(Error::Capacity);
        }
        Ok(Some(Record::new(record_key(intent.operation), &bytes)?))
    }
    fn retained(&mut self, operation: Id) -> Result<Option<Intent>> {
        let raw = self.store.read(record_key(operation));
        let result = raw
            .map_err(Error::from)
            .and_then(|raw| raw.map(|raw| decode_intent(&raw)).transpose());
        if result
            .as_ref()
            .is_err_and(|error| matches!(error, Error::Store(_)))
        {
            self.poisoned = true;
            self.invalidate();
        }
        if result.as_ref().is_ok_and(|value| {
            value
                .as_ref()
                .is_some_and(|intent| intent.operation != operation)
        }) {
            self.poisoned = true;
            self.invalidate();
            return Err(Error::Store(disk::Error::Corrupt));
        }
        result
    }
    fn publish(&mut self, intent: &Intent, record: Record) -> Result<()> {
        let mut next = self.state.clone();
        apply(&mut next, intent, record.as_bytes().len())?;
        let image = encode_state(&next)?;
        self.poisoned = true;
        if let Err(error) = self.store.publish(Some(&self.image), &image, &[record]) {
            if matches!(error, disk::Error::Conflict | disk::Error::Refused) {
                // The store guarantees a rolled-back transaction for these
                // errors. Recheck our exact prior state before retaining live
                // drivers; a semantic refusal alone is not global uncertainty.
                if let Err(check) = check_store(&mut self.store, &self.state, &self.image) {
                    self.invalidate();
                    return Err(check);
                }
                self.poisoned = false;
                return Err(if error == disk::Error::Conflict {
                    Error::Conflict
                } else {
                    Error::Refused
                });
            } else {
                self.invalidate();
            }
            return Err(error.into());
        }
        if let Err(error) = check_store(&mut self.store, &next, &image) {
            self.invalidate();
            return Err(error);
        }
        self.state = next;
        self.image = image;
        self.poisoned = false;
        Ok(())
    }
    pub(super) fn check(&mut self) -> Result<()> {
        if self.poisoned {
            return Err(Error::Store(disk::Error::Uncertain));
        }
        if let Err(error) = check_store(&mut self.store, &self.state, &self.image) {
            self.poisoned = true;
            self.invalidate();
            return Err(error);
        }
        Ok(())
    }
}

fn apply(state: &mut State, intent: &Intent, bytes: usize) -> Result<()> {
    validate(intent)?;
    if intent.context.account.as_bytes() != &state.account.0 {
        return Err(Error::RoomMismatch);
    }
    if let Some(old) = state.slots.get(&intent.slot) {
        if old.context != intent.context {
            return Err(Error::RoomMismatch);
        }
    } else if state.slots.len() >= MAX_ROOMS {
        return Err(Error::Capacity);
    }
    state.slots.insert(
        intent.slot,
        Selected {
            context: intent.context,
            active: match intent.action {
                Action::Attach(_) => Some(intent.operation),
                Action::Detach => None,
            },
        },
    );
    state.operations = state.operations.checked_add(1).ok_or(Error::Capacity)?;
    state.bytes = state
        .bytes
        .checked_add(bytes as u64)
        .ok_or(Error::Capacity)?;
    Ok(())
}
fn validate(intent: &Intent) -> Result<()> {
    if intent.operation.0 == [0; 16] || intent.slot.0 == [0; 16] {
        return Err(Error::Invalid);
    }
    if let Action::Attach(profile) = &intent.action {
        path_bytes(&profile.path)?;
        if profile.hash.0 == [0; 32] {
            return Err(Error::Invalid);
        }
    }
    Ok(())
}
fn path_bytes(path: &Path) -> Result<&str> {
    let value = path.to_str().ok_or(Error::Invalid)?;
    if !path.is_absolute()
        || path.components().collect::<PathBuf>().as_os_str() != path.as_os_str()
        || value.len() > PATH_BYTES
        || value.bytes().any(|b| b < 32 || b == 127)
        || path.file_name().is_none()
        || path
            .components()
            .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
    {
        return Err(Error::Invalid);
    }
    Ok(value)
}
fn store_context(account: Hash) -> Result<disk::Context> {
    Ok(disk::Context::new(
        Sha256::digest(b"valhalla/headless/private-delivery/v1").into(),
        account.0,
    )?)
}
fn record_key(operation: Id) -> [u8; 33] {
    let mut key = [0; 33];
    key[0] = 1;
    let mut hash = Sha256::new();
    hash.update(b"valhalla/headless/private-delivery/operation/v1\0");
    hash.update(operation.0);
    key[1..].copy_from_slice(&hash.finalize());
    key
}
fn put_context(out: &mut Vec<u8>, context: Context) {
    for value in [
        context.scope.room.as_bytes(),
        context.scope.anchor.as_bytes(),
        context.account.as_bytes(),
        context.device.as_bytes(),
    ] {
        out.extend_from_slice(value);
    }
}
fn read<const N: usize>(raw: &mut &[u8]) -> Result<[u8; N]> {
    let (head, tail) = raw
        .split_at_checked(N)
        .ok_or(Error::Store(disk::Error::Corrupt))?;
    *raw = tail;
    head.try_into()
        .map_err(|_| Error::Store(disk::Error::Corrupt))
}
fn get_context(raw: &mut &[u8]) -> Result<Context> {
    let invalid = |_| Error::Store(disk::Error::Corrupt);
    Ok(Context {
        scope: PrivateRoomScope {
            room: RoomId::from_bytes(read(raw)?).map_err(invalid)?,
            anchor: AnchorId::from_bytes(read(raw)?).map_err(invalid)?,
        },
        account: Key::from_bytes(read(raw)?).map_err(invalid)?,
        device: Key::from_bytes(read(raw)?).map_err(invalid)?,
    })
}
fn encode_intent(intent: &Intent) -> Result<Vec<u8>> {
    validate(intent)?;
    let mut out = INTENT.to_vec();
    out.push(match intent.action {
        Action::Attach(_) => 1,
        Action::Detach => 2,
    });
    out.extend_from_slice(&intent.operation.0);
    out.extend_from_slice(&intent.slot.0);
    put_context(&mut out, intent.context);
    if let Action::Attach(profile) = &intent.action {
        let path = path_bytes(&profile.path)?;
        out.extend_from_slice(&profile.hash.0);
        out.extend_from_slice(&(path.len() as u16).to_be_bytes());
        out.extend_from_slice(path.as_bytes());
    }
    Ok(out)
}
fn decode_intent(mut raw: &[u8]) -> Result<Intent> {
    if read::<8>(&mut raw)? != *INTENT {
        return Err(Error::Store(disk::Error::Corrupt));
    }
    let [kind] = read(&mut raw)?;
    let operation = Hex(read(&mut raw)?);
    let slot = Hex(read(&mut raw)?);
    let context = get_context(&mut raw)?;
    let action = match kind {
        1 => {
            let hash = Hex(read(&mut raw)?);
            let len = u16::from_be_bytes(read(&mut raw)?) as usize;
            if raw.len() != len || len > PATH_BYTES {
                return Err(Error::Store(disk::Error::Corrupt));
            }
            let path = std::str::from_utf8(raw)
                .map_err(|_| Error::Store(disk::Error::Corrupt))?
                .into();
            raw = &[];
            Action::Attach(Profile { path, hash })
        }
        2 => Action::Detach,
        _ => return Err(Error::Store(disk::Error::Corrupt)),
    };
    let intent = Intent {
        operation,
        slot,
        context,
        action,
    };
    if !raw.is_empty() || validate(&intent).is_err() {
        return Err(Error::Store(disk::Error::Corrupt));
    }
    Ok(intent)
}
fn encode_state(state: &State) -> Result<Vec<u8>> {
    if state.account.0 == [0; 32] || state.slots.len() > MAX_ROOMS || state.operations > 1_000_000 {
        return Err(Error::Invalid);
    }
    let mut out = IMAGE.to_vec();
    out.extend_from_slice(&state.account.0);
    out.extend_from_slice(&state.operations.to_be_bytes());
    out.extend_from_slice(&state.bytes.to_be_bytes());
    out.push(state.slots.len() as u8);
    for (id, slot) in &state.slots {
        out.extend_from_slice(&id.0);
        put_context(&mut out, slot.context);
        out.extend_from_slice(&slot.active.map_or([0; 16], |id| id.0));
    }
    Ok(out)
}
fn decode_state(mut raw: &[u8]) -> Result<State> {
    if read::<8>(&mut raw)? != *IMAGE {
        return Err(Error::Store(disk::Error::Corrupt));
    }
    let account = Hex(read(&mut raw)?);
    let operations = u64::from_be_bytes(read(&mut raw)?);
    let bytes = u64::from_be_bytes(read(&mut raw)?);
    let [count] = read(&mut raw)?;
    if usize::from(count) > MAX_ROOMS {
        return Err(Error::Store(disk::Error::Corrupt));
    }
    let mut slots = BTreeMap::new();
    let mut previous = None;
    for _ in 0..count {
        let id = Hex(read(&mut raw)?);
        let context = get_context(&mut raw)?;
        let active = read::<16>(&mut raw)?;
        if id.0 == [0; 16]
            || previous.is_some_and(|prior| id <= prior)
            || context.account.as_bytes() != &account.0
        {
            return Err(Error::Store(disk::Error::Corrupt));
        }
        previous = Some(id);
        slots.insert(
            id,
            Selected {
                context,
                active: (active != [0; 16]).then_some(Hex(active)),
            },
        );
    }
    let state = State {
        account,
        operations,
        bytes,
        slots,
    };
    if !raw.is_empty() || encode_state(&state).is_err() {
        return Err(Error::Store(disk::Error::Corrupt));
    }
    Ok(state)
}
fn check_store(store: &mut Store, state: &State, image: &[u8]) -> Result<()> {
    if store.load()?.as_deref() != Some(image) {
        return Err(Error::Store(disk::Error::Corrupt));
    }
    let accounting = store.accounting()?;
    if accounting.records != state.operations
        || accounting.tip != state.operations
        || accounting.generation != state.operations + 1
        || accounting.bytes != state.bytes
    {
        return Err(Error::Store(disk::Error::Corrupt));
    }
    Ok(())
}
fn context_json(context: Context) -> Value {
    json!({"room":Hex(*context.scope.room.as_bytes()),"anchor":Hex(*context.scope.anchor.as_bytes()),"account":Hex(*context.account.as_bytes()),"device":Hex(*context.device.as_bytes())})
}
fn queue_json(
    jobs: &[JobStatus],
    (count, max_jobs, bytes, max_bytes): (usize, usize, usize, usize),
) -> Value {
    json!({"capacity":{"jobs":count,"max_jobs":max_jobs,"bytes":bytes,"max_bytes":max_bytes},"next":jobs.last().map(|job|job.sequence),"records":jobs.iter().map(|job|json!({"digest":Hex(job.id),"operation":Hex(*job.operation.as_bytes()),"sequence":job.sequence,"state":match job.state{JobState::Pending=>"pending",JobState::Uncertain=>"uncertain",JobState::Retained=>"retained",JobState::Stopped=>"stopped"},"attempts":job.attempts,"next_due":job.next_due,"uncertain":job.uncertain,"position":job.position,"last_error":job.last_error.map(net_error)})).collect::<Vec<_>>()})
}
fn net_error(error: NetError) -> &'static str {
    match error {
        NetError::Connect => "connect",
        NetError::Timeout => "timeout",
        NetError::Denied => "denied",
        NetError::Conflict => "conflict",
        NetError::Capacity => "capacity",
        NetError::Bounds => "bounds",
        NetError::Scope => "scope",
        NetError::Malformed => "malformed",
        NetError::Unavailable => "unavailable",
    }
}

#[cfg(test)]
#[path = "private_delivery_tests.rs"]
mod tests;
