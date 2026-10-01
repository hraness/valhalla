//! Explicit publication and selected-source reads for the headless actor.
//!
//! This manager owns no signing keys, native room handles or spawned tasks.
//! Publication and follower creation start with immutable local intent. Missing
//! expected state is preserved, never initialized again to restore progress.

use super::{
    catalog::{Hash, Hex, Id, MAX_ROOMS},
    network, peer,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hraness_control_kit::{ErrorBody, ErrorCode};
use iroh::Endpoint;
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, VecDeque},
    fs::File,
    future::Future,
    path::{Path, PathBuf},
    pin::Pin,
    task::{Context, Poll},
    time::{Duration, Instant},
};
use vhalla_custody::{self as custody, Owner};
use vhalla_direct_native::{
    Follower, FollowerError, FollowerStatus, Projection, ProjectionDirection, ProjectionError,
    ProjectionStatus, Replica, ReplicaError, RoomSession,
};
use vhalla_direct_room::{PinnedGenesis, RoomId, SignedGenesis, MAX_GENESIS_BYTES};
use vhalla_direct_store::{self as disk, Limits};
use vhalla_direct_sync::{Checkpoint, Coverage, Page, Receiver};

#[path = "public_sync_storage.rs"]
mod storage;
use storage::{Binding, Event, Metadata, Published};

#[path = "public_sync_capacity.rs"]
mod capacity_management;
pub(super) use capacity_management::{StorageComponent, StorageLimits};

const MAX_SOURCES: usize = 8;
const MAX_FLIGHTS: usize = 4;
const PAGE_FRAMES: usize = 8;
const HEAD_INTERVAL: Duration = Duration::from_secs(2);
const CAPACITY_STOP: &str =
    "Sync storage is full; increase retained sync capacity before resuming.";
const DATA_LIMITS: Limits = Limits {
    max_records: 100_000,
    max_record_bytes: 64 * 1024 * 1024,
};
const LEDGER_LIMITS: Limits = Limits {
    max_records: 100_000,
    max_record_bytes: 32 * 1024 * 1024,
};
type Result<T> = std::result::Result<T, ErrorBody>;
type ReadFuture =
    Pin<Box<dyn Future<Output = std::result::Result<peer::ObservedReply, peer::PeerError>> + Send>>;

fn invalid() -> ErrorBody {
    ErrorBody::new(ErrorCode::Usage, "Invalid public sync operation or source.")
}
fn conflict() -> ErrorBody {
    ErrorBody::new(
        ErrorCode::Conflict,
        "This public sync operation or room was already reserved with different settings.",
    )
}
fn unavailable() -> ErrorBody {
    ErrorBody::new(
        ErrorCode::OwnerUnavailable,
        "Public sync state changed or is incomplete; preserve it and explicitly reopen the room or service.",
    )
}
fn not_found() -> ErrorBody {
    ErrorBody::new(
        ErrorCode::NotFound,
        "The public room has not been published by this service.",
    )
}
fn capacity() -> ErrorBody {
    ErrorBody::new(
        ErrorCode::Usage,
        "The public sync room, source or retained-history limit has been reached.",
    )
}
fn valid_id(value: Id) -> Result<()> {
    if value.0 == [0; 16] {
        Err(invalid())
    } else {
        Ok(())
    }
}
fn source_id(source: &network::Source) -> Result<Hash> {
    let address = network::address(source)?;
    let value = Hex(*address.id.as_bytes());
    if value.0 == [0; 32] {
        return Err(invalid());
    }
    Ok(value)
}

struct Directory {
    path: PathBuf,
    file: File,
    owner: Owner,
}
impl Directory {
    fn resolved(path: &Path) -> Result<PathBuf> {
        let path = custody::absolute(path).map_err(|_| unavailable())?;
        let name = path.file_name().ok_or_else(unavailable)?;
        let parent = path.parent().ok_or_else(unavailable)?;
        // Resolve existing ancestors (including macOS /var) exactly once. Keep
        // the final component untouched so custody still refuses a symlink.
        Ok(parent.canonicalize().map_err(|_| unavailable())?.join(name))
    }
    fn create(path: &Path) -> Result<Self> {
        let path = Self::resolved(path)?;
        let parent = path.parent().ok_or_else(unavailable)?;
        let (parent_file, owner) =
            custody::open_private_directory(parent).map_err(|_| unavailable())?;
        if owner != Owner::current().map_err(|_| unavailable())? {
            return Err(unavailable());
        }
        let (file, owner) = custody::create_private_directory(&path).map_err(|_| unavailable())?;
        file.sync_all()
            .and_then(|_| parent_file.sync_all())
            .map_err(|_| unavailable())?;
        let result = Self { path, file, owner };
        result.check()?;
        Ok(result)
    }
    fn open(path: &Path) -> Result<Self> {
        let path = Self::resolved(path)?;
        let (file, owner) = custody::open_private_directory(&path).map_err(|_| unavailable())?;
        let result = Self { path, file, owner };
        result.check()?;
        Ok(result)
    }
    fn check(&self) -> Result<()> {
        if self.path.canonicalize().map_err(|_| unavailable())? != self.path {
            return Err(unavailable());
        }
        let (file, owner) =
            custody::open_private_directory(&self.path).map_err(|_| unavailable())?;
        if owner != self.owner
            || owner != Owner::current().map_err(|_| unavailable())?
            || !custody::same_open_file(&file, &self.file).map_err(|_| unavailable())?
        {
            return Err(unavailable());
        }
        Ok(())
    }
}

struct SourceRuntime {
    follower: Option<Follower>,
    opened: bool,
    genesis_checked: bool,
    status: Option<FollowerStatus>,
    last_transport_observation: Option<peer::PathObservation>,
    blocked: bool,
    error: Option<&'static str>,
    failures: u32,
    next_attempt: Instant,
}
impl SourceRuntime {
    fn new() -> Self {
        Self {
            follower: None,
            opened: false,
            genesis_checked: false,
            status: None,
            last_transport_observation: None,
            blocked: false,
            error: None,
            failures: 0,
            next_attempt: Instant::now(),
        }
    }
    fn fail(&mut self, message: &'static str, retry: bool) {
        self.error = Some(message);
        self.failures = self.failures.saturating_add(1);
        self.next_attempt = Instant::now() + Duration::from_secs(1u64 << self.failures.min(5));
        if !retry {
            self.blocked = true;
            self.follower = None;
        }
    }
    fn succeeded(&mut self) {
        self.error = None;
        self.failures = 0;
        self.next_attempt = Instant::now();
    }
}
struct Runtime {
    directory: Directory,
    followers_directory: Directory,
    replica: Replica,
    projection: Projection,
    projected: ProjectionStatus,
    direction: ProjectionDirection,
    sources: BTreeMap<Hash, SourceRuntime>,
    source_after: Option<Hash>,
    capacity_stopped: bool,
    retry_capacity: bool,
}
impl Runtime {
    fn check(&self) -> Result<()> {
        self.directory.check()?;
        self.followers_directory.check()
    }
    fn open(
        path: &Path,
        published: &Published,
        local: Hash,
        room: &mut RoomSession,
    ) -> Result<Self> {
        published.binding.check(room)?;
        let directory = Directory::open(path)?;
        let followers_directory = Directory::open(&path.join("followers"))?;
        let mut replica =
            Replica::open(path.join("replica"), published.binding.genesis()?, local.0)
                .map_err(|_| unavailable())?;
        if let Some(floor) = published.ready {
            let floor: Checkpoint = floor.into();
            if replica
                .page(floor, floor.records, 1)
                .map_err(|_| unavailable())?
                .is_some()
            {
                return Err(unavailable());
            }
        }
        let mut projection = Projection::open(path.join("projection"), room, &mut replica)
            .map_err(|_| unavailable())?;
        let projected = projection
            .status(room, &mut replica)
            .map_err(|_| unavailable())?;
        let result = Self {
            directory,
            followers_directory,
            replica,
            projection,
            projected,
            direction: ProjectionDirection::Outward,
            sources: BTreeMap::new(),
            source_after: None,
            capacity_stopped: false,
            retry_capacity: false,
        };
        result.check()?;
        Ok(result)
    }
}

struct Flight {
    slot: Id,
    peer: Hash,
    selection: Id,
    request: peer::Request,
    future: ReadFuture,
}
struct Completed {
    slot: Id,
    peer: Hash,
    selection: Id,
    request: peer::Request,
    outcome: std::result::Result<peer::AuthenticatedReply, peer::PeerError>,
    observation: Option<peer::PathObservation>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FaultPoint {
    PublishIntent,
    ReplicaCreated,
    ProjectionCreated,
    PublishReady,
    TargetIntent,
    FollowerCreated,
}

/// The caller retains exclusive service custody until this value and every
/// owned network future have been dropped. All network calls are read-only.
pub(super) struct PublicSync {
    metadata: Metadata,
    directory: Directory,
    rooms_directory: Directory,
    runtime: BTreeMap<Id, Runtime>,
    fenced: BTreeMap<Id, &'static str>,
    flights: Vec<Flight>,
    completed: VecDeque<Completed>,
    client: peer::Client,
    maintenance_after: Option<Id>,
    schedule_after: Option<Id>,
    poll_after: usize,
    failed: bool,
    #[cfg(test)]
    fault: Option<FaultPoint>,
}
impl PublicSync {
    pub(super) fn create_new(path: &Path, account: Hash, network_source: Hash) -> Result<Self> {
        if account.0 == [0; 32] || network_source.0 == [0; 32] {
            return Err(invalid());
        }
        let directory = Directory::create(path)?;
        let rooms_directory = Directory::create(&directory.path.join("rooms"))?;
        let metadata =
            Metadata::create_new(&directory.path.join("metadata"), account, network_source)?;
        Self::from_parts(directory, rooms_directory, metadata)
    }
    /// Metadata can be opened before any native room controller is loaded.
    pub(super) fn open(path: &Path, account: Hash, network_source: Hash) -> Result<Self> {
        let directory = Directory::open(path)?;
        let rooms_directory = Directory::open(&directory.path.join("rooms"))?;
        let metadata = Metadata::open(&directory.path.join("metadata"), account, network_source)?;
        Self::from_parts(directory, rooms_directory, metadata)
    }
    fn from_parts(
        directory: Directory,
        rooms_directory: Directory,
        metadata: Metadata,
    ) -> Result<Self> {
        let mut result = Self {
            metadata,
            directory,
            rooms_directory,
            runtime: BTreeMap::new(),
            fenced: BTreeMap::new(),
            flights: Vec::new(),
            completed: VecDeque::new(),
            client: peer::Client::default(),
            maintenance_after: None,
            schedule_after: None,
            poll_after: 0,
            failed: false,
            #[cfg(test)]
            fault: None,
        };
        result.check()?;
        Ok(result)
    }
    pub(super) fn check(&mut self) -> Result<()> {
        if self.failed {
            return Err(unavailable());
        }
        let result = self
            .directory
            .check()
            .and_then(|_| self.rooms_directory.check())
            .and_then(|_| self.metadata.check());
        if result.is_err() {
            self.invalidate();
        }
        result
    }
    /// Global service custody was lost. Drop only this manager's owned reads
    /// and local handles; no new activity is permitted on this value.
    pub(super) fn invalidate(&mut self) {
        self.failed = true;
        self.flights.clear();
        self.completed.clear();
        self.runtime.clear();
    }
    /// Release this room before the caller replaces its native controller.
    /// Only an explicit reopen_room may bind the retained files afterward.
    pub(super) fn close_room(&mut self, slot: Id) {
        if self.metadata.slot(slot).is_ok() {
            self.cancel_room(slot);
            self.runtime.remove(&slot);
            self.fenced.entry(slot).or_insert(
                "The native room was closed; explicitly reopen its retained sync state.",
            );
        }
    }
    /// Safety fences discovered by ticks, status, or peer reads must also revoke
    /// the caller's native room grants. A verified clean capacity stop is absent.
    pub(super) fn fenced_rooms(&self) -> Vec<Id> {
        self.fenced.keys().copied().collect()
    }
    fn path(&self, slot: Id) -> PathBuf {
        self.rooms_directory.path.join(slot.to_string())
    }
    fn hit(&mut self, point: FaultPoint) -> Result<()> {
        let _ = point;
        #[cfg(test)]
        if self.fault == Some(point) {
            self.fault = None;
            self.failed = true;
            return Err(unavailable());
        }
        Ok(())
    }
    fn cancel_room(&mut self, slot: Id) {
        self.flights.retain(|flight| flight.slot != slot);
        self.completed.retain(|reply| reply.slot != slot);
    }
    fn cancel_source(&mut self, slot: Id, peer: Hash) {
        self.flights
            .retain(|flight| flight.slot != slot || flight.peer != peer);
        self.completed
            .retain(|reply| reply.slot != slot || reply.peer != peer);
        if let Some(runtime) = self.runtime.get_mut(&slot) {
            runtime.sources.remove(&peer);
        }
    }
    fn fence(&mut self, slot: Id, message: &'static str) {
        self.cancel_room(slot);
        self.runtime.remove(&slot);
        self.fenced.insert(slot, message);
    }
    pub(super) fn publish(
        &mut self,
        operation: Id,
        slot: Id,
        room: &mut RoomSession,
    ) -> Result<Value> {
        self.check()?;
        let binding = Binding::capture(room)?;
        let fresh = self.metadata.reserve(Event::Publish {
            operation,
            slot,
            binding,
        })?;
        let published = self.metadata.slot(slot)?.clone();
        if self.fenced.contains_key(&slot) {
            return Err(unavailable());
        }
        if let Some(runtime) = self.runtime.get_mut(&slot) {
            let checked = published.binding.check(room).and_then(|_| {
                runtime.check()?;
                runtime.projected = runtime
                    .projection
                    .status(room, &mut runtime.replica)
                    .map_err(|_| unavailable())?;
                Ok(())
            });
            if let Err(error) = checked {
                self.fence(slot, "The retained native room binding has changed.");
                return Err(error);
            }
            return self.status(slot);
        }
        let result: Result<()> = (|| {
            let path = self.path(slot);
            let mut runtime = if fresh {
                self.hit(FaultPoint::PublishIntent)?;
                let directory = Directory::create(&path)?;
                let followers_directory = Directory::create(&path.join("followers"))?;
                let mut replica = Replica::create_new(
                    path.join("replica"),
                    published.binding.genesis()?,
                    self.metadata.source().0,
                    DATA_LIMITS,
                )
                .map_err(|_| unavailable())?;
                self.hit(FaultPoint::ReplicaCreated)?;
                let mut projection = Projection::create_new(
                    path.join("projection"),
                    room,
                    &mut replica,
                    LEDGER_LIMITS,
                )
                .map_err(|_| unavailable())?;
                self.hit(FaultPoint::ProjectionCreated)?;
                let projected = projection
                    .status(room, &mut replica)
                    .map_err(|_| unavailable())?;
                Runtime {
                    directory,
                    followers_directory,
                    replica,
                    projection,
                    projected,
                    direction: ProjectionDirection::Outward,
                    sources: BTreeMap::new(),
                    source_after: None,
                    capacity_stopped: false,
                    retry_capacity: false,
                }
            } else {
                // Reservation is not permission to recreate either component.
                Runtime::open(&path, &published, self.metadata.source(), room)?
            };
            if published.ready.is_none() {
                let checkpoint = runtime.replica.checkpoint().map_err(|_| unavailable())?;
                self.metadata.reserve(Event::Ready {
                    slot,
                    backing: checkpoint.into(),
                })?;
                self.hit(FaultPoint::PublishReady)?;
            }
            runtime.check()?;
            self.runtime.insert(slot, runtime);
            self.check()?;
            Ok(())
        })();
        if result.is_err() {
            self.fence(
                slot,
                "Publication is incomplete; preserve the existing files.",
            );
        }
        result?;
        self.status(slot)
    }
    pub(super) fn configure_source(
        &mut self,
        operation: Id,
        slot: Id,
        source: network::Source,
    ) -> Result<Value> {
        self.check()?;
        let peer = source_id(&source)?;
        if self.metadata.reserve(Event::Configure {
            operation,
            slot,
            source,
        })? {
            self.cancel_source(slot, peer);
        }
        self.status(slot)
    }
    pub(super) fn disable_source(&mut self, operation: Id, slot: Id, peer: Hash) -> Result<Value> {
        self.check()?;
        if self.metadata.reserve(Event::Disable {
            operation,
            slot,
            peer,
        })? {
            self.cancel_source(slot, peer);
        }
        self.status(slot)
    }
    /// An explicit reopen may recover intact retained state. No missing file is
    /// created, and publication/source histories keep their original identities.
    pub(super) fn reopen_room(&mut self, slot: Id, room: &mut RoomSession) -> Result<Value> {
        self.check()?;
        let published = self.metadata.slot(slot)?.clone();
        if published.ready.is_none() {
            return Err(unavailable());
        }
        self.cancel_room(slot);
        let stopped_direction = self
            .runtime
            .remove(&slot)
            .and_then(|live| live.capacity_stopped.then_some(live.direction));
        match Runtime::open(&self.path(slot), &published, self.metadata.source(), room) {
            Ok(mut runtime) => {
                // Reopening alone is not evidence that storage limits grew.
                // Permit one explicit retry while keeping the capacity report
                // until the exact retained projection intent actually advances.
                if let Some(direction) = stopped_direction {
                    runtime.capacity_stopped = true;
                    runtime.retry_capacity = true;
                    runtime.direction = direction;
                }
                self.runtime.insert(slot, runtime);
                self.fenced.remove(&slot);
            }
            Err(error) => {
                self.fence(slot, "Retained room sync state could not be reopened.");
                return Err(error);
            }
        }
        self.status(slot)
    }
    /// This cursor is independent of both network completion and admission.
    /// Call regularly even while completions remain continuously ready.
    pub(super) fn next_room(&mut self) -> Option<Id> {
        if self.failed {
            return None;
        }
        let ids: Vec<_> = self
            .metadata
            .ids()
            .filter(|slot| {
                self.metadata
                    .slot(*slot)
                    .is_ok_and(|value| value.ready.is_some())
                    && !self.fenced.contains_key(slot)
            })
            .collect();
        let id = rotated(&ids, self.maintenance_after).first().copied()?;
        self.maintenance_after = Some(id);
        Some(id)
    }
    /// Poll actor-owned futures only. One ready reply is retained until its room
    /// turn applies it. Dropping this manager cancels every connection in flight.
    pub(super) fn poll_network(&mut self, cx: &mut Context<'_>) -> Poll<Id> {
        if self.failed {
            return Poll::Pending;
        }
        if let Some(reply) = self.completed.front() {
            return Poll::Ready(reply.slot);
        }
        let count = self.flights.len();
        for offset in 0..count {
            let index = (self.poll_after + offset) % count;
            if let Poll::Ready(outcome) = self.flights[index].future.as_mut().poll(cx) {
                let flight = self.flights.remove(index);
                self.poll_after = index;
                let slot = flight.slot;
                let (outcome, observation) = match outcome {
                    Ok(value) => (Ok(value.response), Some(value.observation)),
                    Err(error) => (Err(error), None),
                };
                self.completed.push_back(Completed {
                    slot,
                    peer: flight.peer,
                    selection: flight.selection,
                    request: flight.request,
                    outcome,
                    observation,
                });
                return Poll::Ready(slot);
            }
        }
        Poll::Pending
    }
    pub(super) fn tick_room(
        &mut self,
        slot: Id,
        room: &mut RoomSession,
        endpoint: Option<&Endpoint>,
    ) -> Result<()> {
        self.check()?;
        let published = self.metadata.slot(slot)?.clone();
        if published.ready.is_none() || self.fenced.contains_key(&slot) {
            return Err(unavailable());
        }
        if !self.runtime.contains_key(&slot) {
            match Runtime::open(&self.path(slot), &published, self.metadata.source(), room) {
                Ok(runtime) => {
                    self.runtime.insert(slot, runtime);
                }
                Err(error) => {
                    self.fence(slot, "Retained room sync state could not be opened.");
                    return Err(error);
                }
            }
        }
        let mut runtime = self.runtime.remove(&slot).ok_or_else(unavailable)?;
        let result = (|| {
            runtime.check()?;
            published.binding.check(room)?;
            runtime.projected = runtime
                .projection
                .status(room, &mut runtime.replica)
                .map_err(|_| unavailable())?;
            if runtime.capacity_stopped && !runtime.retry_capacity {
                return runtime.check();
            }
            runtime.retry_capacity = false;
            if let Some(index) = self.completed.iter().position(|reply| reply.slot == slot) {
                let reply = self.completed.remove(index).ok_or_else(unavailable)?;
                self.apply_reply(slot, &published, &mut runtime, reply)?;
            }
            let direction = runtime.projected.pending.unwrap_or(runtime.direction);
            let step = match runtime
                .projection
                .step(direction, room, &mut runtime.replica)
            {
                Ok(step) => step,
                Err(
                    ProjectionError::Store(disk::Error::Refused)
                    | ProjectionError::Replica(ReplicaError::Store(disk::Error::Refused)),
                ) => {
                    // A capacity refusal is only nonfatal after proving that
                    // native custody and the exact retained projection remain
                    // usable. Never discard or reset a known pending intent.
                    published.binding.check(room)?;
                    runtime.projected = runtime
                        .projection
                        .status(room, &mut runtime.replica)
                        .map_err(|_| unavailable())?;
                    runtime.check()?;
                    runtime.capacity_stopped = true;
                    runtime.direction = direction;
                    self.cancel_room(slot);
                    return Ok(());
                }
                Err(_) => return Err(unavailable()),
            };
            runtime.projected = step.status;
            runtime.capacity_stopped = false;
            runtime.direction = match direction {
                ProjectionDirection::Outward => ProjectionDirection::Inward,
                ProjectionDirection::Inward => ProjectionDirection::Outward,
            };
            runtime.check()?;
            Ok(())
        })();
        if let Err(error) = result {
            self.fence(
                slot,
                "Room sync needs an explicit reopen after a native or storage failure.",
            );
            return Err(error);
        }
        self.runtime.insert(slot, runtime);
        self.check()?;
        if let Some(endpoint) = endpoint {
            self.schedule_one(endpoint)?;
        }
        Ok(())
    }

    fn busy(&self, slot: Id) -> bool {
        self.flights.iter().any(|flight| flight.slot == slot)
            || self.completed.iter().any(|reply| reply.slot == slot)
    }
    /// Admission rotates over all loaded rooms, never just the room that freed
    /// a permit. One outstanding request per room also bounds source buffering.
    fn schedule_one(&mut self, endpoint: &Endpoint) -> Result<()> {
        if self.flights.len() + self.completed.len() >= MAX_FLIGHTS {
            return Ok(());
        }
        if *endpoint.id().as_bytes() != self.metadata.source().0 {
            return Err(unavailable());
        }
        let ids: Vec<_> = self.runtime.keys().copied().collect();
        for slot in rotated(&ids, self.schedule_after) {
            if self.busy(slot) || self.fenced.contains_key(&slot) {
                continue;
            }
            if self
                .runtime
                .get(&slot)
                .is_some_and(|live| live.capacity_stopped)
            {
                continue;
            }
            let published = self.metadata.slot(slot)?.clone();
            let mut runtime = self.runtime.remove(&slot).ok_or_else(unavailable)?;
            if runtime.check().is_err() {
                self.fence(slot, "The public sync folder has changed.");
                continue;
            }
            let peers: Vec<_> = published.selected.keys().copied().collect();
            let candidate = rotated(&peers, runtime.source_after)
                .into_iter()
                .find(|peer| {
                    runtime.sources.get(peer).is_none_or(|source| {
                        !source.blocked && source.next_attempt <= Instant::now()
                    })
                });
            let Some(peer) = candidate else {
                self.runtime.insert(slot, runtime);
                continue;
            };
            self.schedule_after = Some(slot);
            runtime.source_after = Some(peer);
            let prepared = self.prepare_request(slot, peer, &published, &mut runtime);
            if self.fenced.contains_key(&slot) {
                self.cancel_room(slot);
                return Ok(());
            }
            self.runtime.insert(slot, runtime);
            let request = match prepared {
                Ok(request) => request,
                Err(error) => {
                    // Metadata failure is global; source/replica failures were
                    // already classified by prepare_request.
                    self.check()?;
                    return Err(error);
                }
            };
            let Some(request) = request else {
                return Ok(());
            };
            let selected = published.selected.get(&peer).ok_or_else(unavailable)?;
            let address = network::address(&selected.source)?;
            let client = self.client.clone();
            let endpoint = endpoint.clone();
            let wire_request = request.clone();
            self.flights.push(Flight {
                slot,
                peer,
                selection: selected.operation,
                request,
                future: Box::pin(async move {
                    client.call_observed(&endpoint, address, wire_request).await
                }),
            });
            return Ok(());
        }
        Ok(())
    }

    fn prepare_request(
        &mut self,
        slot: Id,
        peer: Hash,
        published: &Published,
        runtime: &mut Runtime,
    ) -> Result<Option<peer::Request>> {
        let source = runtime
            .sources
            .entry(peer)
            .or_insert_with(SourceRuntime::new);
        if !source.opened {
            source.opened = true;
            let path = runtime.followers_directory.path.join(peer.to_string());
            if let Some(initial) = self.metadata.initial_target(slot, peer)? {
                let opened = Follower::open(
                    &path,
                    published.binding.genesis()?,
                    peer.0,
                    &mut runtime.replica,
                )
                .map_err(source_open_error)
                .and_then(|mut follower| {
                    if follower.initial_target(&mut runtime.replica)? != initial {
                        return Err(FollowerError::Store(disk::Error::Corrupt));
                    }
                    source.status = Some(follower.status(&mut runtime.replica)?);
                    Ok(follower)
                });
                match opened {
                    Ok(follower) => source.follower = Some(follower),
                    Err(error) => {
                        if follower_room_failure(error) {
                            self.fenced.insert(
                                slot,
                                "The shared public replica needs an explicit reopen.",
                            );
                        }
                        source.fail("The retained source history could not be reopened.", false);
                        return Ok(None);
                    }
                }
            } else {
                match std::fs::symlink_metadata(&path) {
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    _ => {
                        source.fail(
                            "Source files exist without their initial target intent.",
                            false,
                        );
                        return Ok(None);
                    }
                }
            }
        }
        if self.fenced.contains_key(&slot) {
            return Ok(None);
        }
        let room = RoomId::from_bytes(published.binding.room.0);
        if !source.genesis_checked {
            return Ok(Some(peer::Request::Genesis { room }));
        }
        if let Some(follower) = &mut source.follower {
            match follower.status(&mut runtime.replica) {
                Ok(status) => source.status = Some(status),
                Err(error) => {
                    if follower_room_failure(error) {
                        self.fenced
                            .insert(slot, "The shared public replica needs an explicit reopen.");
                    }
                    source.fail(
                        "The retained source progress changed or is unavailable.",
                        false,
                    );
                    return Ok(None);
                }
            }
        }
        if let Some(status) = source.status {
            if status.coverage == Coverage::Pending {
                return Ok(Some(peer::Request::Page {
                    room,
                    checkpoint: status.target,
                    after: status.progress.records,
                    limit: PAGE_FRAMES,
                }));
            }
        }
        Ok(Some(peer::Request::Head { room }))
    }

    fn apply_reply(
        &mut self,
        slot: Id,
        published: &Published,
        runtime: &mut Runtime,
        reply: Completed,
    ) -> Result<()> {
        let Some(selected) = published.selected.get(&reply.peer) else {
            return Ok(());
        };
        if selected.operation != reply.selection {
            return Ok(());
        }
        let Some(source) = runtime.sources.get_mut(&reply.peer) else {
            return Ok(());
        };
        if source.blocked {
            return Ok(());
        }
        let response = match reply.outcome {
            Ok(response) => response,
            Err(error) => {
                let retry = matches!(
                    error,
                    peer::PeerError::Capacity
                        | peer::PeerError::Timeout
                        | peer::PeerError::Unavailable
                );
                source.fail("The selected source did not return a usable reply.", retry);
                return Ok(());
            }
        };
        if response.source != reply.peer.0 {
            source.fail(
                "The reply came from a different authenticated source.",
                false,
            );
            return Ok(());
        }
        // Local, transient evidence only. It cannot change a native checkpoint,
        // source selection, authentication result or durable replay decision.
        source.last_transport_observation = reply.observation;
        let follower_result = match (reply.request, response.reply) {
            (peer::Request::Genesis { .. }, peer::Reply::Genesis(raw)) => {
                if raw != published.binding.genesis()?.encode() {
                    source.fail(
                        "The source genesis does not match the independently pinned room.",
                        false,
                    );
                } else {
                    source.genesis_checked = true;
                    source.succeeded();
                }
                return Ok(());
            }
            (peer::Request::Head { .. }, peer::Reply::Head(target)) => {
                if let Some(follower) = &mut source.follower {
                    follower.extend(response.source, target, &mut runtime.replica)
                } else {
                    if Receiver::begin(
                        published.binding.genesis()?,
                        reply.peer.0,
                        response.source,
                        target,
                    )
                    .is_err()
                    {
                        source.fail(
                            "The source checkpoint does not match its identity or pinned room.",
                            false,
                        );
                        return Ok(());
                    }
                    let fresh = match self.metadata.reserve(Event::Target {
                        slot,
                        peer: reply.peer,
                        selection: reply.selection,
                        target: target.into(),
                    }) {
                        Ok(fresh) => fresh,
                        Err(error)
                            if matches!(error.code, ErrorCode::Usage | ErrorCode::Conflict) =>
                        {
                            source.fail(
                                "The selected source could not reserve retained sync metadata.",
                                false,
                            );
                            return Ok(());
                        }
                        Err(error) => return Err(error),
                    };
                    self.hit(FaultPoint::TargetIntent)?;
                    let path = runtime
                        .followers_directory
                        .path
                        .join(reply.peer.to_string());
                    let follower = if fresh {
                        Follower::create_new(
                            &path,
                            published.binding.genesis()?,
                            reply.peer.0,
                            response.source,
                            target,
                            &mut runtime.replica,
                            LEDGER_LIMITS,
                        )
                    } else {
                        Follower::open(
                            &path,
                            published.binding.genesis()?,
                            reply.peer.0,
                            &mut runtime.replica,
                        )
                        .map_err(source_open_error)
                    };
                    match follower {
                        Ok(mut follower) => {
                            self.hit(FaultPoint::FollowerCreated)?;
                            match follower.initial_target(&mut runtime.replica) {
                                Ok(initial) if initial == target => {
                                    let status = follower.status(&mut runtime.replica);
                                    source.follower = Some(follower);
                                    status
                                }
                                Ok(_) => Err(FollowerError::Store(disk::Error::Corrupt)),
                                Err(error) => Err(error),
                            }
                        }
                        Err(error) => Err(error),
                    }
                }
            }
            (
                peer::Request::Page {
                    checkpoint,
                    after,
                    limit,
                    ..
                },
                peer::Reply::Page(Some(page)),
            ) => {
                if page.checkpoint != checkpoint
                    || page.first != after.saturating_add(1)
                    || page.frames.len() > limit
                    || page.frames.len() > PAGE_FRAMES
                {
                    source.fail(
                        "The source page does not match the requested frozen range.",
                        false,
                    );
                    return Ok(());
                }
                let Some(follower) = &mut source.follower else {
                    source.fail("The source progress is unavailable.", false);
                    return Ok(());
                };
                let frames: Vec<_> = page.frames.iter().map(|frame| frame.as_frame()).collect();
                follower
                    .receive(
                        response.source,
                        Page {
                            checkpoint_id: page.checkpoint.id(),
                            first: page.first,
                            last: page.last,
                            frames: &frames,
                        },
                        &mut runtime.replica,
                    )
                    .map(|outcome| outcome.status)
            }
            (peer::Request::Page { .. }, peer::Reply::Page(None)) => {
                source.fail(
                    "The source stopped before its frozen snapshot was complete.",
                    true,
                );
                return Ok(());
            }
            _ => {
                source.fail(
                    "The source reply did not match the requested operation.",
                    false,
                );
                return Ok(());
            }
        };
        match follower_result {
            Ok(status) => {
                source.status = Some(status);
                source.succeeded();
                if status.coverage == Coverage::Complete {
                    source.next_attempt += HEAD_INTERVAL;
                }
            }
            Err(error) => {
                if follower_room_failure(error) {
                    return Err(unavailable());
                }
                source.fail(
                    "The source history or progress could not be verified; reopen it explicitly.",
                    false,
                );
            }
        }
        Ok(())
    }

    pub(super) fn status(&mut self, slot: Id) -> Result<Value> {
        self.check()?;
        let published = self.metadata.slot(slot)?.clone();
        let mut checkpoint = None;
        if !self.fenced.contains_key(&slot) {
            if let Some(runtime) = self.runtime.get_mut(&slot) {
                if runtime.check().is_err() {
                    self.fence(slot, "The public sync folder has changed.");
                } else {
                    match runtime.replica.checkpoint() {
                        Ok(value) => checkpoint = Some(checkpoint_json(value)),
                        Err(_) => {
                            self.fence(slot, "The shared public replica needs an explicit reopen.")
                        }
                    }
                }
            }
        }
        let runtime = self
            .runtime
            .get(&slot)
            .filter(|_| !self.fenced.contains_key(&slot));
        let sources: Vec<_> = published.selected.iter().map(|(peer, selected)| {
            let live = runtime.and_then(|room| room.sources.get(peer));
            json!({ "peer": peer, "selection": selected.operation, "source": selected.source,
                "state": live.map_or("unopened", |source| if source.blocked { "needs_reopen" } else { "selected" }),
                "last_error": live.and_then(|source| source.error),
                "verified": live.and_then(|source| source.status).map(follower_json),
                "last_transport_observation": live.and_then(|source| source.last_transport_observation),
                "request_pending": self.flights.iter().any(|flight| flight.slot == slot && flight.peer == *peer),
            })
        }).collect();
        Ok(
            json!({ "slot": slot, "room": published.binding.room, "published": published.ready.is_some(),
                "source": self.metadata.source(),
                "state": if self.fenced.contains_key(&slot) { "needs_reopen" } else if runtime.is_some_and(|live| live.capacity_stopped) { "capacity" } else if runtime.is_some() { "ready" } else { "unopened" },
                "last_error": self.fenced.get(&slot).copied().or_else(|| runtime.filter(|live| live.capacity_stopped).map(|_| CAPACITY_STOP)), "local_replica": checkpoint,
                "last_native_projection": runtime.map(|live| projection_json(live.projected)),
                "selected_sources": sources,
            }),
        )
    }

    /// Only explicitly registered, loaded and healthy replicas can be served.
    /// No public wire request reaches native signing or administrative methods.
    pub(super) fn peer_request(
        &mut self,
        request: peer::Request,
    ) -> std::result::Result<peer::Reply, peer::PeerError> {
        self.check().map_err(|_| peer::PeerError::Unavailable)?;
        let slot = self
            .metadata
            .ids()
            .find(|slot| {
                self.metadata.slot(*slot).is_ok_and(|published| {
                    published.ready.is_some()
                        && published.binding.room.0 == *request.room().as_bytes()
                })
            })
            .ok_or(peer::PeerError::Unavailable)?;
        if self.fenced.contains_key(&slot) {
            return Err(peer::PeerError::Unavailable);
        }
        let runtime = self
            .runtime
            .get_mut(&slot)
            .ok_or(peer::PeerError::Unavailable)?;
        if runtime.check().is_err() {
            self.fence(slot, "The public sync folder has changed.");
            return Err(peer::PeerError::Unavailable);
        }
        let result = match request {
            peer::Request::Genesis { .. } => runtime.replica.checkpoint().and_then(|head| {
                runtime.replica.page(head, 0, 1).and_then(|page| {
                    let frame = page
                        .and_then(|page| page.frames.into_iter().next())
                        .ok_or(ReplicaError::Store(disk::Error::Corrupt))?;
                    if frame.kind != vhalla_direct_sync::FrameKind::Genesis {
                        return Err(ReplicaError::Store(disk::Error::Corrupt));
                    }
                    Ok(peer::Reply::Genesis(frame.bytes))
                })
            }),
            peer::Request::Head { .. } => runtime.replica.checkpoint().map(peer::Reply::Head),
            peer::Request::Page {
                checkpoint,
                after,
                limit,
                ..
            } => runtime
                .replica
                .page(checkpoint, after, limit)
                .map(peer::Reply::Page),
        };
        match result {
            Ok(reply) => Ok(reply),
            Err(ReplicaError::Sync(_)) => Err(peer::PeerError::Scope),
            Err(_) => {
                self.fence(slot, "The shared public replica needs an explicit reopen.");
                Err(peer::PeerError::Unavailable)
            }
        }
    }
}

fn rotated<T: Copy + Ord>(items: &[T], after: Option<T>) -> Vec<T> {
    let start = after.map_or(0, |after| items.partition_point(|item| *item <= after));
    items[start..]
        .iter()
        .chain(items[..start].iter())
        .copied()
        .collect()
}
fn follower_room_failure(error: FollowerError) -> bool {
    matches!(
        error,
        FollowerError::Backing
            | FollowerError::Replica(ReplicaError::Store(
                disk::Error::Corrupt | disk::Error::Conflict | disk::Error::Uncertain
            ))
    )
}
fn source_open_error(error: FollowerError) -> FollowerError {
    // A not-yet-opened follower's stored backing identity/references are source
    // claims. They cannot fence an independently checked healthy shared replica.
    // Explicit errors from that replica retain their room-failure provenance;
    // Backing from an already verified live follower remains a room failure.
    match error {
        FollowerError::Backing => FollowerError::Store(disk::Error::Corrupt),
        error => error,
    }
}
fn checkpoint_json(checkpoint: Checkpoint) -> Value {
    json!({ "source": Hex(checkpoint.source), "room": Hex(*checkpoint.room.as_bytes()),
        "epoch": Hex(checkpoint.epoch), "records": checkpoint.records,
        "bytes": checkpoint.bytes, "digest": Hex(checkpoint.digest) })
}
fn follower_json(status: FollowerStatus) -> Value {
    json!({ "target": checkpoint_json(status.target),
        "progress": { "records": status.progress.records, "bytes": status.progress.bytes,
            "digest": Hex(status.progress.digest) },
        "coverage": if status.coverage == Coverage::Complete { "complete" } else { "pending" },
        "backing_floor": checkpoint_json(status.backing_floor) })
}
fn projection_json(status: ProjectionStatus) -> Value {
    json!({ "outward_cursor": status.outward_cursor, "inward_cursor": status.inward_cursor,
        "native_tip": status.native_tip, "replica_tip": status.replica_tip,
        "pending": status.pending.map(|direction| match direction {
            ProjectionDirection::Outward => "outward", ProjectionDirection::Inward => "inward" }),
        "backing_floor": checkpoint_json(status.backing_floor) })
}

#[cfg(test)]
#[path = "public_sync_tests.rs"]
mod tests;
