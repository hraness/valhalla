//! One actor joins trusted administration with retained scoped agent grants.
//!
//! The local transport owns service custody and encloses dispatch plus its final
//! audits in the output gate. No accepted native work is detached or cancelled
//! when a requesting connection goes away.

use super::{
    access::{self, GrantSpec, Registry},
    backend::{Backend, PreparedAdmin},
    catalog::{Hash, Id},
    local::{self, Channel, Reply},
};
use hraness_control_kit::{ErrorBody, ErrorCode};
use serde::Deserialize;
use serde_json::{json, Value};
use std::path::Path;

#[path = "service_runtime.rs"]
mod runtime;
use runtime::Facilities;

type Result<T> = std::result::Result<T, ErrorBody>;

#[derive(Deserialize)]
#[serde(tag = "op", deny_unknown_fields)]
enum GrantAdmin {
    #[serde(rename = "grant.issue")]
    Issue {
        operation: Id,
        room: Id,
        grant: Box<GrantSpec>,
    },
    #[serde(rename = "grant.revoke")]
    Revoke { generation: Hash, token: Hash },
}

pub(super) struct ServiceBackend {
    // Closing output authority precedes dropping any room or account custody.
    registry: Registry,
    // Read futures and delivery workers end before native signing custody.
    facilities: Facilities,
    backend: Backend,
    generation: Hash,
}

impl ServiceBackend {
    /// Initialize under caller-held exclusive service custody. The caller must
    /// retain that custody for this value's entire lifetime and supply a fresh
    /// process generation. Partial native creation is never retried implicitly.
    pub(super) async fn initialize(home: &Path, generation: Hash) -> Result<Self> {
        let registry = Registry::new(generation)?;
        let backend = Backend::initialize(home).await?;
        let facilities = Facilities::initialize(home, backend.account_key())?;
        Ok(Self {
            registry,
            facilities,
            backend,
            generation,
        })
    }

    /// Open only retained native state under caller-held service custody and a
    /// fresh generation. Durable claims never reconstruct prior grant budgets.
    pub(super) async fn open(home: &Path, generation: Hash) -> Result<Self> {
        let registry = Registry::new(generation)?;
        let backend = Backend::open(home).await?;
        let facilities = Facilities::open(home, backend.account_key())?;
        Ok(Self {
            registry,
            facilities,
            backend,
            generation,
        })
    }

    fn check_global(&mut self) -> Result<()> {
        let result = self.backend.check().and_then(|_| self.facilities.check());
        if result.is_err() {
            self.registry.close_all();
            self.facilities.invalidate();
        }
        result
    }

    /// Called inside the same output exclusion hold as the native dispatch.
    /// Errors and successful owner changes both end every affected old scope.
    fn audit(&mut self) -> Result<()> {
        self.check_global()?;
        for id in self.facilities.public.fenced_rooms() {
            self.fail_room(id);
        }
        for id in self.backend.loaded_room_ids() {
            match self.backend.checked_loaded_room_mut(id) {
                Ok(room) => self.registry.audit_room(id, room),
                Err(_) => self.close_room(id),
            }
        }
        // Native checks can discover a replaced shared directory or catalog.
        self.check_global()
    }

    async fn admin(&mut self, value: Value) -> Result<Reply> {
        if runtime::is_request(&value) {
            return self.runtime_admin(value).await.map(Reply::unrestricted);
        }
        if matches!(
            value.get("op").and_then(Value::as_str),
            Some("grant.issue" | "grant.revoke")
        ) {
            let request: GrantAdmin = serde_json::from_value(value).map_err(|_| usage())?;
            return match request {
                GrantAdmin::Issue {
                    operation,
                    room,
                    grant,
                } => {
                    let (session, catalog) = match self.backend.room_and_catalog_mut(room).await {
                        Ok(parts) => parts,
                        Err(error) => {
                            self.close_room(room);
                            return Err(error);
                        }
                    };
                    self.registry
                        .issue(catalog, operation, room, session, *grant)
                }
                GrantAdmin::Revoke { generation, token } => {
                    if generation != self.generation {
                        return Err(ErrorBody::new(
                            ErrorCode::PermissionDenied,
                            "The grant belongs to another service generation.",
                        ));
                    }
                    self.registry.revoke(token);
                    Ok(Reply::unrestricted(
                        json!({"generation":generation,"revoked":true}),
                    ))
                }
            };
        }
        let request = PreparedAdmin::parse(value)?;
        let room = request.room();
        let replacement = request.replacement();
        if let Some(room) = replacement {
            // Reopening identical native authority is still a new custody
            // lifetime, so a queued reply from the old handle cannot survive.
            self.close_room(room);
        }
        let mut result = self.backend.dispatch_prepared(request).await;
        if result
            .as_ref()
            .is_err_and(|error| error.code == ErrorCode::OwnerUnavailable)
        {
            if let Some(room) = room {
                self.fail_room(room);
            }
        }
        if result.is_ok() {
            if let Some(room) = replacement {
                self.reopen_sync(room).await?;
            }
            if let Ok(value) = &mut result {
                // The account status is the only response with this shape.
                if value.get("headless").is_some() {
                    value["network"] = self.facilities.network_status()?;
                }
            }
        }
        result.map(Reply::unrestricted)
    }

    async fn agent(&mut self, value: Value) -> Result<Reply> {
        let request = access::parse(value)?;
        let id = self.registry.room_for(&request)?;
        let room = match self.backend.room_mut(id).await {
            Ok(room) => room,
            Err(error) => {
                self.close_room(id);
                return Err(error);
            }
        };
        let result = self.registry.handle(room, request).await;
        if result
            .as_ref()
            .is_err_and(|error| error.code == ErrorCode::OwnerUnavailable)
        {
            // A native read can reject authenticated records while its cached
            // status still looks healthy. Close sibling grants and retain the
            // failure fence; a later successful status is not reconciliation.
            self.fail_room(id);
        }
        result
    }
}

impl local::Backend for ServiceBackend {
    async fn dispatch(&mut self, channel: Channel, request: Value) -> Result<Reply> {
        self.check_global()?;
        let result = match channel {
            Channel::Admin => self.admin(request).await,
            Channel::Agent => self.agent(request).await,
        };
        // This intentionally runs even after parsing, permission, conflict or
        // native errors. No early-return branch may bypass final revocation.
        self.audit()?;
        result
    }

    async fn tick(&mut self) -> Result<()> {
        self.runtime_tick().await
    }

    async fn peer(
        &mut self,
        _authenticated_peer: [u8; 32],
        request: super::peer::Request,
    ) -> std::result::Result<super::peer::Reply, super::peer::PeerError> {
        self.audit()
            .map_err(|_| super::peer::PeerError::Unavailable)?;
        let result = self.facilities.public.peer_request(request);
        self.audit()
            .map_err(|_| super::peer::PeerError::Unavailable)?;
        result
    }

    fn invalidate(&mut self) {
        self.registry.close_all();
        self.facilities.invalidate();
    }
}

fn usage() -> ErrorBody {
    ErrorBody::new(
        ErrorCode::Usage,
        "Invalid scoped grant administration request.",
    )
}

#[cfg(test)]
#[path = "service_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "service_runtime_tests.rs"]
mod runtime_tests;

#[cfg(test)]
#[path = "service_private_tests.rs"]
mod private_tests;

#[cfg(test)]
#[path = "service_recovery_tests.rs"]
mod recovery_tests;
