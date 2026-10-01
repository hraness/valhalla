//! Background work and owner-only network configuration share the service actor.

use super::*;
use crate::headless::{
    backend::Room, network, private_delivery, private_setup, public_sync::PublicSync,
};
use iroh::Endpoint;
use std::{future::poll_fn, path::PathBuf, task::Poll};

pub(super) struct Facilities {
    // Managers end their read futures/workers before transport identity is dropped.
    pub(super) public: PublicSync,
    private: private_delivery::Manager,
    identity: network::Identity,
    endpoint: Option<Endpoint>,
    listen: Option<network::Listen>,
    private_after: Option<Id>,
    failed: bool,
}

impl Facilities {
    pub(super) fn initialize(home: &Path, account: Hash) -> Result<Self> {
        let identity = network::Identity::create_new(home)?;
        let public = PublicSync::create_new(&home.join("public-sync"), account, identity.id())?;
        let private =
            private_delivery::Manager::initialize(&home.join("private-delivery"), account)
                .map_err(delivery_error)?;
        let mut result = Self {
            public,
            private,
            identity,
            endpoint: None,
            listen: None,
            private_after: None,
            failed: false,
        };
        result.check()?;
        Ok(result)
    }

    pub(super) fn open(home: &Path, account: Hash) -> Result<Self> {
        let identity = network::Identity::open(home)?;
        let public = PublicSync::open(&home.join("public-sync"), account, identity.id())?;
        let private = private_delivery::Manager::open(&home.join("private-delivery"), account)
            .map_err(delivery_error)?;
        let mut result = Self {
            public,
            private,
            identity,
            endpoint: None,
            listen: None,
            private_after: None,
            failed: false,
        };
        result.check()?;
        Ok(result)
    }

    pub(super) fn check(&mut self) -> Result<()> {
        if self.failed {
            return Err(unavailable());
        }
        self.identity.check()?;
        self.public.check()?;
        self.private.check().map_err(delivery_error)
    }

    pub(super) fn invalidate(&mut self) {
        self.failed = true;
        self.public.invalidate();
        self.private.invalidate();
    }

    fn source(&self) -> Result<network::Source> {
        let endpoint = self.endpoint.as_ref().ok_or_else(|| {
            ErrorBody::new(
                ErrorCode::OwnerUnavailable,
                "The public peer listener is not running.",
            )
        })?;
        network::source_with_relay(
            endpoint,
            self.listen.as_ref().and_then(|v| v.relay_url.as_deref()),
        )
    }

    pub(super) fn network_status(&self) -> Result<Value> {
        self.identity.check()?;
        // Address discovery may still be pending; absence is explicit and does
        // not masquerade as a routable invitation or a service-custody failure.
        let source = if self.endpoint.is_some() {
            self.source().ok()
        } else {
            None
        };
        Ok(
            json!({"peer":self.identity.id(), "listening":self.endpoint.is_some(),
            "configured":self.listen, "source":source}),
        )
    }
}

#[derive(Deserialize)]
#[serde(tag = "op", deny_unknown_fields)]
enum Request {
    #[serde(rename = "public.publish")]
    Publish { operation: Id, room: Id },
    #[serde(rename = "public.source")]
    Source {
        operation: Id,
        room: Id,
        source: network::Source,
    },
    #[serde(rename = "public.disable_source")]
    Disable { operation: Id, room: Id, peer: Hash },
    #[serde(rename = "public.sync_status")]
    PublicStatus { room: Id },
    #[serde(rename = "public.sync_storage")]
    PublicStorage { room: Id },
    #[serde(rename = "public.sync_expand_limits")]
    ExpandPublicStorage {
        room: Id,
        component: crate::headless::public_sync::StorageComponent,
        limits: crate::headless::public_sync::StorageLimits,
    },
    #[serde(rename = "public.link")]
    Link { room: Id },
    #[serde(rename = "public.inspect_link")]
    InspectLink { link: String },
    #[serde(rename = "private.delivery_attach")]
    Attach {
        operation: Id,
        room: Id,
        profile: PathBuf,
        profile_hash: Hash,
    },
    #[serde(rename = "private.delivery_init")]
    InitializeDelivery {
        room: Id,
        profile: PathBuf,
        profile_hash: Hash,
    },
    #[serde(rename = "private.delivery_detach")]
    Detach { operation: Id, room: Id },
    #[serde(rename = "private.delivery_status")]
    PrivateStatus { room: Id, after: u64, limit: usize },
}
impl Request {
    fn room(&self) -> Option<Id> {
        match self {
            Self::Publish { room, .. }
            | Self::Source { room, .. }
            | Self::Disable { room, .. }
            | Self::PublicStatus { room }
            | Self::PublicStorage { room }
            | Self::ExpandPublicStorage { room, .. }
            | Self::Link { room }
            | Self::Attach { room, .. }
            | Self::InitializeDelivery { room, .. }
            | Self::Detach { room, .. }
            | Self::PrivateStatus { room, .. } => Some(*room),
            Self::InspectLink { .. } => None,
        }
    }
}

pub(super) fn is_request(value: &Value) -> bool {
    matches!(
        value.get("op").and_then(Value::as_str),
        Some(
            "public.publish"
                | "public.source"
                | "public.disable_source"
                | "public.sync_status"
                | "public.sync_storage"
                | "public.sync_expand_limits"
                | "public.link"
                | "public.inspect_link"
                | "private.delivery_attach"
                | "private.delivery_init"
                | "private.delivery_detach"
                | "private.delivery_status"
        )
    )
}

impl ServiceBackend {
    /// The caller owns exclusive service custody before binding and retains the
    /// returned endpoint through the peer-server drain after invalidation.
    pub(in crate::headless) async fn bind_network(
        &mut self,
        listen: &network::Listen,
    ) -> Result<Endpoint> {
        self.check_global()?;
        if self.facilities.endpoint.is_some() {
            return Err(ErrorBody::new(
                ErrorCode::Conflict,
                "The peer listener is already running.",
            ));
        }
        let endpoint = self.facilities.identity.bind(listen).await?;
        if let Err(error) = self.check_global() {
            endpoint.close().await;
            return Err(error);
        }
        self.facilities.listen = Some(listen.clone());
        self.facilities.endpoint = Some(endpoint.clone());
        Ok(endpoint)
    }

    pub(super) fn close_room(&mut self, room: Id) {
        self.registry.close_room(room);
        self.facilities.public.close_room(room);
        self.facilities.private.close_room(room);
    }

    pub(super) fn fail_room(&mut self, room: Id) {
        self.close_room(room);
        self.backend.fail_room(room);
    }

    pub(super) async fn reopen_sync(&mut self, id: Id) -> Result<()> {
        // Unpublished public rooms have no network state to reopen. A private
        // selection remains stopped until an explicit fresh attach operation.
        match self.facilities.public.status(id) {
            Err(error) if error.code == ErrorCode::NotFound => return Ok(()),
            Err(error) => return Err(error),
            Ok(_) => {}
        }
        let result = match self.backend.room_mut(id).await? {
            Room::Public(room) => self.facilities.public.reopen_room(id, room).map(|_| ()),
            Room::Private(_) => Err(unavailable()),
        };
        if result.is_err() {
            self.fail_room(id);
        }
        result
    }

    pub(super) async fn runtime_admin(&mut self, value: Value) -> Result<Value> {
        let request: Request = serde_json::from_value(value).map_err(|_| invalid())?;
        let room_id = request.room();
        let result = self.runtime_request(request).await;
        if result
            .as_ref()
            .is_err_and(|error| error.code == ErrorCode::OwnerUnavailable)
        {
            if let Some(id) = room_id {
                self.fail_room(id);
            }
        }
        result
    }

    async fn runtime_request(&mut self, request: Request) -> Result<Value> {
        match request {
            Request::Publish {
                operation,
                room: id,
            } => {
                let Room::Public(room) = self.backend.room_mut(id).await? else {
                    return Err(wrong_kind());
                };
                self.facilities.public.publish(operation, id, room)
            }
            Request::Source {
                operation,
                room: id,
                source,
            } => {
                if !matches!(self.backend.room_mut(id).await?, Room::Public(_)) {
                    return Err(wrong_kind());
                }
                self.facilities
                    .public
                    .configure_source(operation, id, source)
            }
            Request::Disable {
                operation,
                room: id,
                peer,
            } => self.facilities.public.disable_source(operation, id, peer),
            Request::PublicStatus { room } => self.facilities.public.status(room),
            Request::PublicStorage { room: id } => {
                let Room::Public(room) = self.backend.room_mut(id).await? else {
                    return Err(wrong_kind());
                };
                self.facilities.public.storage_status(id, room)
            }
            Request::ExpandPublicStorage {
                room: id,
                component,
                limits,
            } => {
                let Room::Public(room) = self.backend.room_mut(id).await? else {
                    return Err(wrong_kind());
                };
                self.facilities
                    .public
                    .expand_storage(id, room, component, limits)
            }
            Request::Link { room: id } => {
                let published = self.facilities.public.status(id)?;
                if published["state"] != "ready" || published["published"] != true {
                    return Err(ErrorBody::new(
                        ErrorCode::Conflict,
                        "Publish and open this public room before sharing its link.",
                    ));
                }
                let source = self.facilities.source().map_err(|_| {
                    ErrorBody::new(
                        ErrorCode::Conflict,
                        "A usable peer address is not available yet.",
                    )
                })?;
                let Room::Public(room) = self.backend.room_mut(id).await? else {
                    return Err(wrong_kind());
                };
                let link = network::RoomLink::new(room.genesis(), source)?;
                Ok(json!({"room":id, "pin":link.pin, "link":link.encode()?}))
            }
            Request::InspectLink { link } => {
                let link = network::RoomLink::parse(&link)?;
                let genesis = link.validate()?;
                let bytes = genesis.encode();
                let encoded: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
                Ok(json!({"pin":link.pin, "genesis":encoded, "source":link.source}))
            }
            Request::Attach {
                operation,
                room: id,
                profile,
                profile_hash,
            } => {
                let Room::Private(room) = self.backend.room_mut(id).await? else {
                    return Err(wrong_kind());
                };
                let context = room.status().map_err(|_| unavailable())?.context;
                self.facilities
                    .private
                    .attach(operation, id, context, profile, profile_hash)
                    .map_err(delivery_error)
            }
            Request::InitializeDelivery {
                room: id,
                profile,
                profile_hash,
            } => {
                let Room::Private(room) = self.backend.room_mut(id).await? else {
                    return Err(wrong_kind());
                };
                let context = room.status().map_err(|_| unavailable())?.context;
                private_setup::initialize(&profile, profile_hash, context)
            }
            Request::Detach {
                operation,
                room: id,
            } => {
                let Room::Private(room) = self.backend.room_mut(id).await? else {
                    return Err(wrong_kind());
                };
                let context = room.status().map_err(|_| unavailable())?.context;
                self.facilities
                    .private
                    .detach(operation, id, context)
                    .map_err(delivery_error)
            }
            Request::PrivateStatus { room, after, limit } => self
                .facilities
                .private
                .status(room, after, limit)
                .map_err(delivery_error),
        }
    }

    pub(super) async fn runtime_tick(&mut self) -> Result<()> {
        self.audit()?;
        // Poll even when no completion is ready, then return to the actor. The
        // 250ms maintenance timer guarantees another poll without a busy loop.
        let completed = poll_fn(|cx| {
            Poll::Ready(match self.facilities.public.poll_network(cx) {
                Poll::Ready(room) => Some(room),
                Poll::Pending => None,
            })
        })
        .await;
        if let Some(room) = completed {
            self.public_step(room).await;
        }
        // This separate cursor must advance despite continuous completions.
        if let Some(room) = self.facilities.public.next_room() {
            if completed != Some(room) {
                self.public_step(room).await;
            }
        }
        let rooms = self.facilities.private.active_rooms();
        let selected = rooms
            .iter()
            .copied()
            .find(|id| {
                self.facilities
                    .private_after
                    .is_none_or(|after| *id > after)
            })
            .or_else(|| rooms.first().copied());
        if let Some(id) = selected {
            self.facilities.private_after = Some(id);
            let result = match self.backend.room_mut(id).await {
                Ok(Room::Private(room)) => self.facilities.private.tick_room(id, room).await,
                _ => Err(private_delivery::Error::NativeUnavailable),
            };
            if result == Err(private_delivery::Error::NativeUnavailable) {
                self.fail_room(id);
            }
            // A profile/relay refusal stops only that driver. The manager
            // retains its reason; the final audit detects shared-store loss.
        }
        self.audit()
    }

    async fn public_step(&mut self, id: Id) {
        let result = match self.backend.room_mut(id).await {
            Ok(Room::Public(room)) => {
                self.facilities
                    .public
                    .tick_room(id, room, self.facilities.endpoint.as_ref())
            }
            _ => Err(unavailable()),
        };
        if result
            .as_ref()
            .is_err_and(|error| error.code == ErrorCode::OwnerUnavailable)
        {
            self.fail_room(id);
        }
    }
}

fn invalid() -> ErrorBody {
    ErrorBody::new(
        ErrorCode::Usage,
        "Invalid public sync or private delivery request.",
    )
}
fn wrong_kind() -> ErrorBody {
    ErrorBody::new(
        ErrorCode::Usage,
        "This operation does not apply to the selected room kind.",
    )
}
fn unavailable() -> ErrorBody {
    ErrorBody::new(
        ErrorCode::OwnerUnavailable,
        "Retained room or service state needs an explicit reopen.",
    )
}
fn delivery_error(error: private_delivery::Error) -> ErrorBody {
    use private_delivery::Error;
    let (code, message) = match error {
        Error::Invalid | Error::RoomMismatch => (
            ErrorCode::Usage,
            "Invalid private delivery selection or room context.",
        ),
        Error::Conflict | Error::Store(vhalla_direct_store::Error::Conflict) => (
            ErrorCode::Conflict,
            "This delivery operation is already reserved with different settings.",
        ),
        Error::NotFound => (
            ErrorCode::NotFound,
            "This room has no retained delivery selection.",
        ),
        Error::Capacity => (
            ErrorCode::Usage,
            "The private delivery queue is full; preserve it before changing capacity.",
        ),
        Error::StaleProfile
        | Error::Refused
        | Error::Store(vhalla_direct_store::Error::Refused) => (
            ErrorCode::Conflict,
            "The selected delivery profile or queue is unavailable; preserve it and explicitly attach a valid profile.",
        ),
        Error::NativeUnavailable | Error::Store(_) => (
            ErrorCode::OwnerUnavailable,
            "Private native or selection state is unavailable; preserve it and explicitly reopen.",
        ),
    };
    ErrorBody::new(code, message)
}
