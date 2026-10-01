//! Trusted administration over one account and independently verified room slots.
//!
//! The caller holds service custody for this entire value's lifetime. Accepted
//! mutations stay on that actor; dropping a request never starts detached work.

mod wire;

use super::catalog::{commitment, Catalog, Hash, Hex, Id, Kind, Locator, MAX_ROOMS};
use hraness_control_kit::{ErrorBody, ErrorCode};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use vhalla_custody::{self as custody, Owner};
use vhalla_direct_native as public;
use vhalla_direct_room::{RoomId as PublicRoomId, SignedGenesis};
use vhalla_identity::Identity;
use vhalla_private_kernel::{
    protocol::{AnchorId, Key, PrivateRoomScope, RoomId as PrivateRoomId, Validity},
    CommittedOutbox, ContactBootstrap, Context, OperationId, OutboxKind, Phase,
};
use vhalla_private_native::client::{self as private, AccountController};
use wire::*;

pub(super) enum Room {
    Public(Box<public::RoomSession>),
    Private(Box<private::RoomSession>),
}

/// A strictly decoded admin call, with only lifecycle metadata exposed to the
/// service. Private bootstrap artifacts remain owned by this one request.
pub(super) struct PreparedAdmin(Request);

impl PreparedAdmin {
    pub(super) fn parse(value: Value) -> Result<Self, ErrorBody> {
        serde_json::from_value(value)
            .map(Self)
            .map_err(|_| usage("The admin request has unknown fields or invalid values."))
    }

    pub(super) fn room(&self) -> Option<Id> {
        self.0.room_id()
    }

    pub(super) fn replacement(&self) -> Option<Id> {
        match self.0 {
            Request::Reopen { room } => Some(room),
            _ => None,
        }
    }
}

struct Directory {
    path: PathBuf,
    file: File,
    owner: Owner,
}

impl Directory {
    fn open(path: PathBuf, create: bool) -> Result<Self, ErrorBody> {
        let (file, owner) = if create {
            custody::create_private_directory(&path)
        } else {
            custody::open_private_directory(&path)
        }
        .map_err(|_| unsafe_home())?;
        if owner != Owner::current().map_err(|_| unsafe_home())? {
            return Err(unsafe_home());
        }
        Ok(Self { path, file, owner })
    }

    fn check(&self) -> Result<(), ErrorBody> {
        let (file, owner) =
            custody::open_private_directory(&self.path).map_err(|_| unsafe_home())?;
        if owner != self.owner
            || owner != Owner::current().map_err(|_| unsafe_home())?
            || !custody::same_open_file(&file, &self.file).map_err(|_| unsafe_home())?
        {
            return Err(unsafe_home());
        }
        Ok(())
    }

    fn sync(&self) -> Result<(), ErrorBody> {
        self.check()?;
        self.file.sync_all().map_err(|_| recovery())
    }
}

pub(super) struct Backend {
    // Release every room before the account's final shared custody hold.
    rooms: BTreeMap<Id, Room>,
    failed_rooms: BTreeSet<Id>,
    catalog: Catalog,
    directories: [Directory; 4],
    failed: bool,
    account: AccountController,
}

impl Backend {
    /// Initialize only absent native namespaces inside the caller-owned home.
    /// Partial initialization is preserved; this is never a repair operation.
    pub(super) async fn initialize(home: &Path) -> Result<Self, ErrorBody> {
        let home = Directory::open(custody::absolute(home).map_err(|_| unsafe_home())?, false)?;
        let rooms = Directory::open(home.path.join("rooms"), true)?;
        home.sync()?;
        let public = Directory::open(rooms.path.join("public"), true)?;
        rooms.sync()?;
        let private = Directory::open(rooms.path.join("private"), true)?;
        rooms.sync()?;
        home.check()?;
        let account = AccountController::new(
            Identity::create_new(home.path.join("account")).map_err(|_| recovery())?,
        );
        home.check()?;
        let catalog = Catalog::create_new(&home.path.join("catalog"), Hex(account.public_key()))
            .map_err(store_error)?;
        let mut result = Self {
            rooms: BTreeMap::new(),
            failed_rooms: BTreeSet::new(),
            catalog,
            directories: [home, rooms, public, private],
            failed: false,
            account,
        };
        result.check()?;
        Ok(result)
    }

    /// Existing-only startup. Individual rooms open lazily and fail independently.
    pub(super) async fn open(home: &Path) -> Result<Self, ErrorBody> {
        let home = Directory::open(custody::absolute(home).map_err(|_| unsafe_home())?, false)?;
        let rooms = Directory::open(home.path.join("rooms"), false)?;
        let public = Directory::open(rooms.path.join("public"), false)?;
        let private = Directory::open(rooms.path.join("private"), false)?;
        home.check()?;
        let account = AccountController::new(
            Identity::open(home.path.join("account")).map_err(|_| recovery())?,
        );
        let catalog = Catalog::open(&home.path.join("catalog"), Hex(account.public_key()))
            .map_err(store_error)?;
        let mut result = Self {
            rooms: BTreeMap::new(),
            failed_rooms: BTreeSet::new(),
            catalog,
            directories: [home, rooms, public, private],
            failed: false,
            account,
        };
        result.check()?;
        Ok(result)
    }

    pub(super) fn check(&mut self) -> Result<(), ErrorBody> {
        if self.failed {
            return Err(recovery());
        }
        for directory in &self.directories {
            if let Err(error) = directory.check() {
                self.failed = true;
                return Err(error);
            }
        }
        self.catalog.check().map_err(store_error)
    }

    pub(super) fn loaded_room_ids(&self) -> Vec<Id> {
        self.rooms.keys().copied().collect()
    }

    pub(super) fn account_key(&self) -> Hash {
        Hex(self.account.public_key())
    }

    #[cfg(test)]
    pub(super) fn loaded_room_mut(&mut self, id: Id) -> Option<&mut Room> {
        self.rooms.get_mut(&id)
    }

    /// Retain a room-level uncertainty fence even when a cached native status
    /// still succeeds. Only the explicit existing-state reopen path clears it.
    pub(super) fn fail_room(&mut self, id: Id) {
        if self.catalog.slot(id).is_some() {
            self.failed_rooms.insert(id);
        }
    }

    /// Inspect only an already loaded controller. A native recovery latch is
    /// retained at the room boundary even when its first error was Conflict.
    /// No caller may use this helper to reopen or clear a failed controller.
    pub(super) fn checked_loaded_room_mut(&mut self, id: Id) -> Result<&mut Room, ErrorBody> {
        if self.failed_rooms.contains(&id) {
            return Err(room_recovery());
        }
        let room = self.rooms.get_mut(&id).ok_or_else(not_found)?;
        let healthy = match room {
            Room::Public(room) => room.status().is_ok(),
            Room::Private(room) => room.status().is_ok(),
        };
        if !healthy {
            self.failed_rooms.insert(id);
            return Err(room_recovery());
        }
        Ok(room)
    }

    /// Borrow the one current controller and catalog together to consume a
    /// scoped authorization. Loading uses the existing-only recovery path.
    pub(super) async fn room_and_catalog_mut(
        &mut self,
        id: Id,
    ) -> Result<(&mut Room, &mut Catalog), ErrorBody> {
        self.room_mut(id).await?;
        Ok((
            self.rooms.get_mut(&id).ok_or_else(internal)?,
            &mut self.catalog,
        ))
    }

    /// The caller uses this only for scoped grant claim publication, never to
    /// reconstruct a consumed grant's budget from a retained receipt.
    #[cfg(test)]
    pub(super) fn catalog_mut(&mut self) -> Result<&mut Catalog, ErrorBody> {
        self.check()?;
        Ok(&mut self.catalog)
    }

    fn room_path(&self, id: Id, kind: Kind) -> PathBuf {
        self.directories[match kind {
            Kind::Public => 2,
            Kind::Private => 3,
        }]
        .path
        .join(id.to_string())
    }

    pub(super) async fn room_mut(&mut self, id: Id) -> Result<&mut Room, ErrorBody> {
        self.check()?;
        if self.failed_rooms.contains(&id) {
            return Err(room_recovery());
        }
        if !self.rooms.contains_key(&id) {
            let result = self.open_slot(id).await;
            match result {
                Ok(room) => {
                    self.rooms.insert(id, room);
                }
                Err(error) => {
                    if self.catalog.slot(id).is_some() {
                        self.failed_rooms.insert(id);
                    }
                    return Err(error);
                }
            }
        }
        self.rooms.get_mut(&id).ok_or_else(internal)
    }

    async fn open_slot(&mut self, id: Id) -> Result<Room, ErrorBody> {
        let slot = self.catalog.slot(id).cloned().ok_or_else(not_found)?;
        let path = self.room_path(id, slot.kind);
        let mut room =
            match slot.locator {
                Some(Locator::Public { pin }) => Room::Public(Box::new(
                    self.account
                        .open_public_room(&path, PublicRoomId::from_bytes(pin.0))
                        .map_err(public_error)?,
                )),
                Some(locator @ Locator::Private { .. }) => Room::Private(Box::new(
                    self.account
                        .open_room(&path, private_context(locator)?)
                        .await
                        .map_err(private_error)?,
                )),
                None if slot.kind == Kind::Public => {
                    // Only public creation reserves a missing locator. A marker is
                    // a hint: the account, native author and signed owner state must
                    // all verify before the catalog can bind this recovered pin.
                    let context = vhalla_direct_store::Store::locate_context(path.join("store"))
                        .map_err(|_| room_recovery())?;
                    if context.as_bytes()[32..] != self.account.public_key() {
                        return Err(room_recovery());
                    }
                    let pin = Hex(context.as_bytes()[..32]
                        .try_into()
                        .map_err(|_| internal())?);
                    if self.catalog.slots().iter().any(|other| {
                        other.id != id && other.locator == Some(Locator::Public { pin })
                    }) {
                        return Err(room_recovery());
                    }
                    let room = self
                        .account
                        .open_public_room(&path, PublicRoomId::from_bytes(pin.0))
                        .map_err(public_error)?;
                    Room::Public(Box::new(room))
                }
                None => return Err(room_recovery()),
            };
        if let Room::Public(public) = &mut room {
            self.check_public_provenance(id, public)?;
            if slot.locator.is_none() {
                self.catalog
                    .bind(
                        id,
                        Locator::Public {
                            pin: Hex(*public.room_id().as_bytes()),
                        },
                    )
                    .map_err(store_error)?;
            }
        }
        self.check()?;
        self.catalog.complete(id).map_err(store_error)?;
        Ok(room)
    }

    /// Trusted admin requests only. The transport performs admin authentication;
    /// this dispatcher never accepts a grant token as administrative authority.
    #[cfg(test)]
    pub(super) async fn dispatch_admin(&mut self, request: Value) -> Result<Value, ErrorBody> {
        self.check()?;
        self.dispatch_prepared(PreparedAdmin::parse(request)?).await
    }

    pub(super) async fn dispatch_prepared(
        &mut self,
        request: PreparedAdmin,
    ) -> Result<Value, ErrorBody> {
        self.check()?;
        let request = request.0;
        let intent = request.creation_intent()?;
        let id = request.room_id();
        let result = self.dispatch(request, intent).await;
        if result
            .as_ref()
            .is_err_and(|error| error.code == ErrorCode::OwnerUnavailable)
        {
            if let Some(id) = id.filter(|id| self.catalog.slot(*id).is_some()) {
                self.failed_rooms.insert(id);
            }
        }
        // A successful native mutation cannot justify releasing content through
        // replaced service directories. Native uncertainty stays in that slot.
        self.check()?;
        if let Ok(value) = &result {
            bound_response(value)?;
        }
        result
    }

    async fn dispatch(
        &mut self,
        request: Request,
        intent: Option<Hash>,
    ) -> Result<Value, ErrorBody> {
        match request {
            Request::ServiceStatus {} => {
                let storage = self.catalog.accounting().map_err(store_error)?;
                Ok(json!({
                    "account": Hex(self.account.public_key()), "rooms": self.catalog.slots().len(),
                    "open_rooms": self.rooms.len(), "failed_rooms": self.failed_rooms.len(),
                    "max_rooms": MAX_ROOMS, "headless": true, "consumed_grants": self.catalog.grant_claims(),
                    "storage": accounting(storage),
                }))
            }
            Request::ExpandService { limits } => {
                limits.check(Kind::Private)?;
                let current = self.catalog.accounting().map_err(store_error)?;
                ensure_growing(limits, current.limits)?;
                let grown = self
                    .catalog
                    .expand_limits(limits.public())
                    .map_err(store_error)?;
                Ok(json!({"storage": accounting(grown)}))
            }
            Request::RoomList {} => Ok(
                json!({ "rooms": self.catalog.slots().iter().map(|slot| json!({
                "room": slot.id, "kind": slot.kind, "initialized": slot.ready,
                "open": self.rooms.contains_key(&slot.id),
                "needs_reopen": self.failed_rooms.contains(&slot.id),
                "incomplete": !slot.ready,
            })).collect::<Vec<_>>() }),
            ),
            Request::Create {
                operation,
                kind,
                limits,
                validity,
            } => {
                limits.check(kind)?;
                match kind {
                    Kind::Public if validity.is_some() => {
                        return Err(usage("Public creation does not take a validity interval."));
                    }
                    Kind::Private if validity.is_none() => {
                        return Err(usage("Private creation requires a validity interval."));
                    }
                    _ => {}
                }
                let validity = validity.map(Interval::native).transpose()?;
                if self.catalog.slot(operation).is_none() {
                    if let Some(validity) = validity {
                        validity.check_at(now()?).map_err(|_| {
                            permission("The private validity interval is not current.")
                        })?;
                    }
                }
                if self
                    .catalog
                    .reserve(operation, kind, intent.ok_or_else(internal)?, None)
                    .map_err(store_error)?
                {
                    let path = self.room_path(operation, kind);
                    let nonce = self
                        .catalog
                        .slot(operation)
                        .ok_or_else(internal)?
                        .creation_nonce
                        .0;
                    let created = match kind {
                        Kind::Public => self
                            .account
                            .create_public_room_bound(path, nonce, limits.public())
                            .map(|room| Room::Public(Box::new(room)))
                            .map_err(public_error),
                        Kind::Private => {
                            match self.account.prepare_owner(validity.ok_or_else(internal)?) {
                                Ok(creation) => {
                                    self.catalog
                                        .bind(operation, locator(creation.context()))
                                        .map_err(store_error)?;
                                    creation
                                        .commit(path, limits.private())
                                        .await
                                        .map(|room| Room::Private(Box::new(room)))
                                        .map_err(private_error)
                                }
                                Err(error) => Err(private_error(error)),
                            }
                        }
                    };
                    self.finish_creation(operation, created)?;
                }
                room_status(operation, self.room_mut(operation).await?).await
            }
            Request::JoinPublic {
                operation,
                genesis,
                pin,
                limits,
            } => {
                limits.check(Kind::Public)?;
                SignedGenesis::decode(&genesis.0)
                    .and_then(|value| value.verify_pin(PublicRoomId::from_bytes(pin.0)))
                    .map_err(|_| {
                        usage("The signed genesis does not match the selected public room pin.")
                    })?;
                if self
                    .catalog
                    .reserve(
                        operation,
                        Kind::Public,
                        intent.ok_or_else(internal)?,
                        Some(Locator::Public { pin }),
                    )
                    .map_err(store_error)?
                {
                    let nonce = self
                        .catalog
                        .slot(operation)
                        .ok_or_else(internal)?
                        .creation_nonce
                        .0;
                    let result = self
                        .account
                        .join_public_room_bound(
                            self.room_path(operation, Kind::Public),
                            &genesis.0,
                            PublicRoomId::from_bytes(pin.0),
                            nonce,
                            limits.public(),
                        )
                        .map(|room| Room::Public(Box::new(room)))
                        .map_err(public_error);
                    self.finish_creation(operation, result)?;
                }
                room_status(operation, self.room_mut(operation).await?).await
            }
            Request::JoinPrivate {
                operation,
                offer,
                expected_owner,
                validity,
                limits,
            } => {
                limits.check(Kind::Private)?;
                let validity = validity.native()?;
                let expected_owner = key(expected_owner)?;
                if self.catalog.slot(operation).is_none() {
                    let time = now()?;
                    validity
                        .check_at(time)
                        .map_err(|_| permission("The private validity interval is not current."))?;
                    ContactBootstrap::inspect(&offer.0, expected_owner, key(Hex(self.account.public_key()))?, time)
                        .map_err(|_| permission("The confidential offer does not authorize this account under the selected owner."))?;
                }
                if self
                    .catalog
                    .reserve(operation, Kind::Private, intent.ok_or_else(internal)?, None)
                    .map_err(store_error)?
                {
                    let creation = self
                        .account
                        .prepare_contact_member(&offer.0, expected_owner, validity)
                        .map_err(private_error)?;
                    self.catalog
                        .bind(operation, locator(creation.context()))
                        .map_err(store_error)?;
                    let result = creation
                        .commit(self.room_path(operation, Kind::Private), limits.private())
                        .await
                        .map(|room| Room::Private(Box::new(room)))
                        .map_err(private_error);
                    self.finish_creation(operation, result)?;
                }
                let room = private_room(self.room_mut(operation).await?)?;
                let request = room
                    .contact_request(operation_id(operation)?, &offer.0)
                    .await
                    .map_err(private_error)?;
                let output = artifact(request.bytes())?;
                let status = private_status(operation, room).await?;
                Ok(
                    json!({"room": operation, "status": status, "request": output, "delivery": "unconfirmed"}),
                )
            }
            Request::Status { room } => room_status(room, self.room_mut(room).await?).await,
            Request::Reopen { room } => {
                // The integration owner must invalidate this room's release
                // permits before calling this method, even if reopening succeeds
                // under an unchanged policy or roster.
                self.catalog.slot(room).ok_or_else(not_found)?;
                self.rooms.remove(&room);
                self.failed_rooms.remove(&room);
                room_status(room, self.room_mut(room).await?).await
            }
            Request::Send {
                room,
                operation,
                body,
                epoch,
                roster,
            } => {
                if body.is_empty() || body.len() > 4096 {
                    return Err(usage("A message must contain 1 through 4096 UTF-8 bytes."));
                }
                match self.room_mut(room).await? {
                    Room::Public(room) => {
                        if epoch.is_some() || roster.is_some() {
                            return Err(usage(
                                "Public sends do not take a private epoch or roster.",
                            ));
                        }
                        let outcome = room
                            .send(operation.0, &body, now()?)
                            .map_err(public_error)?;
                        Ok(public_operation(outcome))
                    }
                    Room::Private(room) => {
                        let epoch = epoch.ok_or_else(|| {
                            usage("Private sends require the selected epoch and roster.")
                        })?;
                        let roster = roster.ok_or_else(|| {
                            usage("Private sends require the selected epoch and roster.")
                        })?;
                        let operation = operation_id(operation)?;
                        // Retry the exact original disclosure before inspecting
                        // current membership. Never recreate a historical draft.
                        if let Some(retained) = room
                            .retained_send(operation, epoch, roster.0, body.as_bytes())
                            .await
                            .map_err(private_error)?
                        {
                            return private_operation(&retained, Some(true));
                        }
                        let snapshot = room.membership().await.map_err(private_error)?;
                        let status = snapshot.status();
                        let time = now()?;
                        if status.quarantined
                            || matches!(status.phase, Phase::AwaitingWelcome | Phase::Removed)
                            || snapshot.local().claims().validity.check_at(time).is_err()
                            || snapshot.owner().claims().validity.check_at(time).is_err()
                        {
                            return Err(permission(
                                "Current private membership does not authorize a new message.",
                            ));
                        }
                        if status.epoch != epoch || status.roster != roster.0 {
                            return Err(conflict(
                                "The selected recipients changed; inspect the room before authorizing a new message.",
                            ));
                        }
                        let draft = room
                            .prepare_message(body.as_bytes())
                            .map_err(private_error)?;
                        let sent = room.send(operation, &draft).await.map_err(private_error)?;
                        private_operation(&sent, Some(false))
                    }
                }
            }
            Request::Messages { room, after, limit } => {
                messages(self.room_mut(room).await?, after, limit).await
            }
            Request::Outbox { room, after, limit } => {
                outbox(self.room_mut(room).await?, after, limit).await
            }
            Request::ExpandPublic { room: id, limits } => {
                limits.check(Kind::Public)?;
                let room = self.room_mut(id).await?;
                let public = public_room(room)?;
                ensure_growing(
                    limits,
                    public.status().map_err(public_error)?.storage.limits,
                )?;
                public
                    .expand_limits(limits.public())
                    .map_err(public_error)?;
                room_status(id, room).await
            }
            Request::ReconcilePublic { room: id } => {
                let room = self.room_mut(id).await?;
                public_room(room)?.reconcile().map_err(public_error)?;
                room_status(id, room).await
            }
            Request::SetWriters {
                room,
                operation,
                writers,
            } => {
                if writers.is_empty() || writers.len() > vhalla_direct_room::MAX_WRITERS {
                    return Err(usage(
                        "The public writer list is outside the supported range.",
                    ));
                }
                let room = public_room(self.room_mut(room).await?)?;
                let result = room
                    .set_writers(
                        operation.0,
                        writers.into_iter().map(|value| value.0).collect(),
                    )
                    .map_err(public_error)?;
                Ok(public_operation(result))
            }
            Request::Offer {
                room,
                operation,
                recipient,
                validity,
            } => {
                let recipient = key(recipient)?;
                let validity = validity.native()?;
                let result = private_room(self.room_mut(room).await?)?
                    .create_contact_offer(operation_id(operation)?, recipient, validity)
                    .await
                    .map_err(private_error)?;
                Ok(
                    json!({"operation": operation, "offer": artifact(result.confidential_bytes())?, "transfer": "confidential", "delivery": "unconfirmed"}),
                )
            }
            Request::AcceptContact {
                room,
                operation,
                request,
                validity,
            } => {
                let validity = validity.native()?;
                let result = private_room(self.room_mut(room).await?)?
                    .accept_contact(operation_id(operation)?, &request.0, validity)
                    .await
                    .map_err(private_error)?;
                private_operation(&result, None)
            }
            Request::JoinContact { room, response } => {
                let session = private_room(self.room_mut(room).await?)?;
                session
                    .join_contact(&response.0)
                    .await
                    .map_err(private_error)?;
                private_status(room, session).await
            }
            Request::Remove {
                room,
                operation,
                device,
            } => {
                let device = key(device)?;
                let result = private_room(self.room_mut(room).await?)?
                    .remove(operation_id(operation)?, device)
                    .await
                    .map_err(private_error)?;
                private_operation(&result, None)
            }
        }
    }

    fn finish_creation(
        &mut self,
        id: Id,
        created: Result<Room, ErrorBody>,
    ) -> Result<(), ErrorBody> {
        let mut room = created.inspect_err(|_| {
            self.failed_rooms.insert(id);
        })?;
        self.check()?;
        if let Room::Public(room) = &mut room {
            self.check_public_provenance(id, room)?;
            self.catalog
                .bind(
                    id,
                    Locator::Public {
                        pin: Hex(*room.room_id().as_bytes()),
                    },
                )
                .map_err(store_error)?;
        }
        self.catalog.complete(id).map_err(store_error)?;
        self.rooms.insert(id, room);
        Ok(())
    }

    fn check_public_provenance(
        &mut self,
        id: Id,
        room: &mut public::RoomSession,
    ) -> Result<(), ErrorBody> {
        let slot = self.catalog.slot(id).cloned().ok_or_else(room_recovery)?;
        let created = self.catalog.public_creation_mode(id).map_err(store_error)?;
        let status = room.status().map_err(public_error)?;
        if room.creation_nonce() != slot.creation_nonce.0
            || status.created_here != created
            || (created && room.genesis().claims().nonce != slot.creation_nonce.0)
            || slot.locator.is_some_and(|locator| {
                locator
                    != Locator::Public {
                        pin: Hex(*status.room.as_bytes()),
                    }
            })
        {
            return Err(room_recovery());
        }
        Ok(())
    }
}

fn private_context(value: Locator) -> Result<Context, ErrorBody> {
    let Locator::Private {
        room,
        anchor,
        account,
        device,
    } = value
    else {
        return Err(internal());
    };
    Ok(Context {
        scope: PrivateRoomScope {
            room: PrivateRoomId::from_bytes(room.0).map_err(|_| room_recovery())?,
            anchor: AnchorId::from_bytes(anchor.0).map_err(|_| room_recovery())?,
        },
        account: Key::from_bytes(account.0).map_err(|_| room_recovery())?,
        device: Key::from_bytes(device.0).map_err(|_| room_recovery())?,
    })
}

fn locator(context: Context) -> Locator {
    Locator::Private {
        room: Hex(*context.scope.room.as_bytes()),
        anchor: Hex(*context.scope.anchor.as_bytes()),
        account: Hex(*context.account.as_bytes()),
        device: Hex(*context.device.as_bytes()),
    }
}

fn public_room(room: &mut Room) -> Result<&mut public::RoomSession, ErrorBody> {
    match room {
        Room::Public(room) => Ok(room),
        Room::Private(_) => Err(usage("This operation requires a public room.")),
    }
}

fn private_room(room: &mut Room) -> Result<&mut private::RoomSession, ErrorBody> {
    match room {
        Room::Private(room) => Ok(room),
        Room::Public(_) => Err(usage("This operation requires a private room.")),
    }
}

fn key(value: Hash) -> Result<Key, ErrorBody> {
    Key::from_bytes(value.0).map_err(|_| usage("The selected public key is invalid."))
}

fn operation_id(value: Id) -> Result<OperationId, ErrorBody> {
    OperationId::from_bytes(value.0).map_err(|_| usage("The operation ID is invalid."))
}

fn now() -> Result<u64, ErrorBody> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|time| time.as_secs())
        .map_err(|_| {
            ErrorBody::new(
                ErrorCode::OwnerUnavailable,
                "A valid system clock is required.",
            )
        })
}

async fn room_status(id: Id, room: &mut Room) -> Result<Value, ErrorBody> {
    match room {
        Room::Public(room) => {
            let status = room.status().map_err(public_error)?;
            Ok(json!({
                "room": id, "kind": "public", "pin": Hex(*status.room.as_bytes()),
                "author": Hex(status.author), "owner": Hex(room.genesis().claims().owner),
                "genesis": hex(&room.genesis().encode()), "created_here": status.created_here,
                "policy": {"revision": status.policy.revision, "id": Hex(*status.policy.id.as_bytes())},
                "pending_policy": status.pending_policy.map(|position| json!({"revision": position.revision, "id": Hex(*position.id.as_bytes())})),
                "owner_forked": status.owner_forked, "capacity_fenced": status.capacity_fenced,
                "author_custody_lost": status.author_custody_lost, "owner_custody_lost": status.owner_custody_lost,
                "pending_event_operation": status.pending_event_operation.map(Hex),
                "pending_policy_operation": status.pending_policy_operation.map(Hex),
                "reconciliation_pending": status.reconciliation_pending, "can_send": status.can_send,
                "admission": if status.can_send { "locally_authorized" } else if !status.created_here && status.policy.revision == 0 { "needs_owner_admission" } else { "blocked" },
                "storage": {"records": status.storage.records, "bytes": status.storage.bytes,
                    "max_records": status.storage.limits.max_records, "max_record_bytes": status.storage.limits.max_record_bytes},
                "coverage": "local", "delivery": "unconfirmed",
            }))
        }
        Room::Private(room) => private_status(id, room).await,
    }
}

async fn private_status(id: Id, room: &mut private::RoomSession) -> Result<Value, ErrorBody> {
    let snapshot = room.membership().await.map_err(private_error)?;
    let status = snapshot.status();
    let storage = room.storage_accounting().await.map_err(private_error)?;
    let time = now()?;
    let can_send = !status.quarantined
        && !matches!(status.phase, Phase::AwaitingWelcome | Phase::Removed)
        && snapshot.local().claims().validity.check_at(time).is_ok()
        && snapshot.owner().claims().validity.check_at(time).is_ok();
    Ok(json!({
        "room": id, "kind": "private", "context": locator(status.context),
        "phase": phase(status.phase), "epoch": status.epoch, "roster": Hex(status.roster),
        "members": status.members, "quarantined": status.quarantined, "can_send": can_send,
        "needs_owner_admission": status.phase == Phase::AwaitingWelcome,
        "control_sequence": status.control_floor.sequence(), "control_id": status.control_floor.id().map(|value| Hex(*value.as_bytes())),
        "outbox_head": status.outbox_head, "inbox_head": status.inbox_head,
        "storage": {"records":storage.records,"bytes":storage.bytes,
            "max_records":storage.max_records,"max_record_bytes":storage.max_bytes,
            "immutable_limits":true},
        "recipients": snapshot.members().iter().map(|value| { let claims = value.claims(); json!({
            "account": Hex(*claims.account.as_bytes()), "device": Hex(*claims.device.as_bytes()),
            "not_before": claims.validity.not_before(), "expires_at": claims.validity.expires_at(),
        }) }).collect::<Vec<_>>(),
        "coverage": "local", "delivery": "unconfirmed",
    }))
}

fn phase(value: Phase) -> &'static str {
    match value {
        Phase::OwnerGenesis => "owner_genesis",
        Phase::AwaitingWelcome => "awaiting_welcome",
        Phase::OwnerJoined => "owner_joined",
        Phase::MemberJoined => "member_joined",
        Phase::OwnerAfterRemoval => "owner_after_removal",
        Phase::Removed => "removed",
    }
}

fn visibility(value: public::Visibility) -> &'static str {
    match value {
        public::Visibility::Provisional => "provisional",
        public::Visibility::OwnerSealed => "owner_sealed",
        public::Visibility::ContinuityOnly => "continuity_only",
        public::Visibility::Incomplete => "incomplete",
    }
}

fn operation_state(value: public::OperationState) -> &'static str {
    match value {
        public::OperationState::Provisional => "provisional",
        public::OperationState::OwnerSealed => "owner_sealed",
        public::OperationState::NeedsRepost => "needs_repost",
        public::OperationState::PendingHistory => "pending_history",
        public::OperationState::PolicyApplied => "policy_applied",
    }
}

fn outbox_kind(value: OutboxKind) -> &'static str {
    match value {
        OutboxKind::ContactOffer => "contact_offer",
        OutboxKind::ContactRequest => "contact_request",
        OutboxKind::ContactInvitation => "contact_invitation",
        OutboxKind::KeyPackage => "key_package",
        OutboxKind::Invitation => "invitation",
        OutboxKind::Application => "application",
        OutboxKind::Removal => "removal",
        OutboxKind::OwnerUpdate => "owner_update",
        OutboxKind::Succession => "succession",
    }
}

fn public_operation(value: public::OperationOutcome) -> Value {
    json!({"operation": Hex(value.operation), "state": operation_state(value.state),
        "exact_retry": value.exact_retry, "artifact": hex(&value.bytes), "queued_locally": true, "delivery": "unconfirmed"})
}

fn private_operation(
    value: &CommittedOutbox,
    exact_retry: Option<bool>,
) -> Result<Value, ErrorBody> {
    Ok(
        json!({"operation": Hex(*value.operation().as_bytes()), "sequence": value.sequence(),
        "kind": outbox_kind(value.kind()), "artifact": artifact(value.bytes())?,
        "exact_retry": exact_retry, "queued_locally": true, "delivery": "unconfirmed"}),
    )
}

async fn messages(room: &mut Room, after: u64, limit: usize) -> Result<Value, ErrorBody> {
    match room {
        Room::Public(room) => {
            page_limit(limit, 32)?;
            let page = room.messages(after, limit).map_err(public_error)?;
            Ok(
                json!({"head": page.tip, "next": page.next, "coverage": "local", "records": page.messages.iter().map(|message| {
                let claims = message.event.claims(); json!({"cursor": message.cursor, "event": Hex(*message.event.id().as_bytes()),
                    "author": Hex(claims.author), "body": claims.text.as_str(), "created_at": claims.created_at,
                    "visibility": visibility(message.visibility)})
            }).collect::<Vec<_>>() }),
            )
        }
        Room::Private(room) => {
            page_limit(limit, 16)?;
            let page = room.inbox(after, limit).await.map_err(private_error)?;
            Ok(
                json!({"head": page.head, "next": page.next, "coverage": "local", "records": page.records.iter().map(|message| json!({
                "cursor": message.sequence(), "sender": Hex(*message.sender().as_bytes()),
                "body": std::str::from_utf8(message.body()).ok(), "body_hex": hex(message.body()),
            })).collect::<Vec<_>>() }),
            )
        }
    }
}

async fn outbox(room: &mut Room, after: u64, limit: usize) -> Result<Value, ErrorBody> {
    match room {
        Room::Public(room) => {
            page_limit(limit, 32)?;
            let page = room.operations(after, limit).map_err(public_error)?;
            Ok(
                json!({"head": page.tip, "next": page.next, "delivery": "unconfirmed", "records": page.operations.iter().map(|entry| json!({
                "cursor": entry.cursor, "operation": Hex(entry.operation),
                "kind": match entry.kind { public::OperationKind::Event => "event", public::OperationKind::Policy => "policy" },
                "frame_hash": Hex(entry.frame_hash), "committed_locally": true,
            })).collect::<Vec<_>>() }),
            )
        }
        Room::Private(room) => {
            page_limit(limit, 16)?;
            let page = room.outbox(after, limit).await.map_err(private_error)?;
            let mut records = Vec::with_capacity(page.records.len());
            for entry in &page.records {
                let claims = if entry.kind() == OutboxKind::Application {
                    room.acceptances(entry.sequence())
                        .await
                        .map_err(private_error)?
                } else {
                    Vec::new()
                };
                records.push(json!({
                    "cursor": entry.sequence(), "operation": Hex(*entry.operation().as_bytes()),
                    "kind": outbox_kind(entry.kind()), "queued_locally": true,
                    "member_acceptance_count": claims.len(),
                    "device_acceptances": claims.iter().map(|claim| json!({
                        "recipient": Hex(*claim.recipient().as_bytes()),
                        "ciphertext": Hex(claim.ciphertext()),
                        "received_sequence": claim.received_sequence(),
                    })).collect::<Vec<_>>(),
                }));
            }
            Ok(
                json!({"head": page.head, "next": page.next, "delivery": "unconfirmed", "records": records,
                "acceptance_scope": "Authenticated device processing claims from current roster members; human reading is unknown."}),
            )
        }
    }
}

fn accounting(value: vhalla_direct_store::Accounting) -> Value {
    json!({"records":value.records,"bytes":value.bytes,
        "max_records":value.limits.max_records,"max_record_bytes":value.limits.max_record_bytes})
}

fn ensure_growing(target: Limits, current: vhalla_direct_store::Limits) -> Result<(), ErrorBody> {
    if target.max_records < current.max_records
        || target.max_record_bytes < current.max_record_bytes
    {
        return Err(usage(
            "Storage limits can only grow; retained records are never removed.",
        ));
    }
    Ok(())
}

fn page_limit(limit: usize, max: usize) -> Result<(), ErrorBody> {
    if limit == 0 || limit > max {
        return Err(usage(
            "The selected page size is outside the supported range.",
        ));
    }
    Ok(())
}

fn usage(message: &str) -> ErrorBody {
    ErrorBody::new(ErrorCode::Usage, message)
}
fn permission(message: &str) -> ErrorBody {
    ErrorBody::new(ErrorCode::PermissionDenied, message)
}
fn conflict(message: &str) -> ErrorBody {
    ErrorBody::new(ErrorCode::Conflict, message)
}
fn internal() -> ErrorBody {
    ErrorBody::new(
        ErrorCode::Internal,
        "The service could not complete this request.",
    )
}
fn not_found() -> ErrorBody {
    ErrorBody::new(
        ErrorCode::NotFound,
        "The selected room is not in this service.",
    )
}
fn unsafe_home() -> ErrorBody {
    permission("The service home is unsafe or has changed; preserve it and restart the service.")
}
fn recovery() -> ErrorBody {
    ErrorBody::new(
        ErrorCode::OwnerUnavailable,
        "Preserve the service state and explicitly reopen it before retrying the same operation.",
    )
}
fn room_recovery() -> ErrorBody {
    ErrorBody::new(
        ErrorCode::OwnerUnavailable,
        "Preserve this room and explicitly reopen it before retrying the same operation.",
    )
}

fn store_error(value: vhalla_direct_store::Error) -> ErrorBody {
    match value {
        vhalla_direct_store::Error::Conflict => {
            conflict("This operation ID already records different intent.")
        }
        vhalla_direct_store::Error::Refused => permission(
            "The catalog refused this operation; its limits and retained state are unchanged.",
        ),
        vhalla_direct_store::Error::Uncertain | vhalla_direct_store::Error::Corrupt => recovery(),
    }
}

fn public_error(value: public::Error) -> ErrorBody {
    match value {
        public::Error::Bounds => usage("The public operation exceeds a supported bound."),
        public::Error::OperationConflict => {
            conflict("This operation ID already records different intent.")
        }
        public::Error::NotOwner | public::Error::ReadOnly => {
            permission("The retained public room authority does not permit this operation.")
        }
        public::Error::Capacity => {
            permission("The public room reached its retained-data limit; preserve its history.")
        }
        public::Error::OperationPending => {
            conflict("A retained public operation must finish before a new operation can begin.")
        }
        public::Error::Protocol(_) => {
            permission("The public room protocol refused this operation.")
        }
        public::Error::Custody | public::Error::Corrupt | public::Error::Uncertain => {
            room_recovery()
        }
        public::Error::Entropy => ErrorBody::new(
            ErrorCode::OwnerUnavailable,
            "Fresh operating-system randomness is unavailable.",
        ),
    }
}

fn private_error(value: private::Error) -> ErrorBody {
    use vhalla_private_kernel::Error as Kernel;
    match value {
        private::Error::Kernel(Kernel::Conflict) => {
            conflict("This operation ID or retained private state conflicts with the request.")
        }
        private::Error::Kernel(Kernel::Bounds | Kernel::Encoding) => {
            usage("The private operation exceeds a supported bound or has invalid encoding.")
        }
        private::Error::Storage(vhalla_private_kernel::storage::StoreError::Refused) => permission(
            "The private store refused this operation; preserve its retained state and limits.",
        ),
        private::Error::Locked
        | private::Error::Storage(_)
        | private::Error::Kernel(Kernel::NeedsReopen | Kernel::Missing) => room_recovery(),
        private::Error::Clock => ErrorBody::new(
            ErrorCode::OwnerUnavailable,
            "A valid system clock is required.",
        ),
        _ => permission("The private room protocol or current membership refused this operation."),
    }
}

#[cfg(test)]
#[path = "backend_tests.rs"]
mod tests;
