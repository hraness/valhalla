#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Local authorization for the steel thread.
//!
//! This crate does not parse wire data and does not perform effects. It turns a
//! validated remote request into a private, scope-limited capability only when
//! local policy permits it.

use vhalla_core::{Epoch, EventId, PeerId};

/// The only operation exposed by the first steel thread.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operation {
    /// A bounded in-memory read used by the prototype host.
    ReadMemory,
}

/// A resource scope for an operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Scope {
    /// Operation granted by the policy.
    pub operation: Operation,
    /// Host-defined resource identifier.
    pub resource: u32,
}

/// A request that remains inert until a local policy authorizes it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RemoteRequest {
    /// Event that carried the request.
    pub event_id: EventId,
    /// Peer that authored the request.
    pub author: PeerId,
    /// Requested operation and resource.
    pub scope: Scope,
    /// Opaque model/peer text; this is never interpreted as authority.
    pub content: alloc::vec::Vec<u8>,
}

extern crate alloc;

/// A local policy for one owner/epoch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalPolicy {
    owner: PeerId,
    epoch: Epoch,
    read_resource: Option<u32>,
}

impl LocalPolicy {
    /// Permit one in-memory resource for the owner at this policy epoch.
    #[must_use]
    pub const fn read_memory(owner: PeerId, epoch: Epoch, resource: u32) -> Self {
        Self {
            owner,
            epoch,
            read_resource: Some(resource),
        }
    }

    /// Authorize a request using only local policy; peer content cannot mint a capability.
    pub fn authorize(&self, request: RemoteRequest) -> Result<AuthorizedEffect, Denied> {
        if request.scope.operation != Operation::ReadMemory
            || self.read_resource != Some(request.scope.resource)
        {
            return Err(Denied::Scope);
        }
        Ok(AuthorizedEffect {
            event_id: request.event_id,
            scope: request.scope,
            owner: self.owner,
            epoch: self.epoch,
            consumed: false,
        })
    }
}

/// A capability that can only be created by [`LocalPolicy::authorize`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizedEffect {
    event_id: EventId,
    scope: Scope,
    owner: PeerId,
    epoch: Epoch,
    consumed: bool,
}

impl AuthorizedEffect {
    /// Consume the capability for a host execution at the same owner and epoch.
    pub fn consume(&mut self, owner: PeerId, epoch: Epoch) -> Result<EffectRequest, Denied> {
        if self.consumed {
            return Err(Denied::Consumed);
        }
        if owner != self.owner {
            return Err(Denied::Owner);
        }
        if epoch != self.epoch {
            return Err(Denied::Epoch);
        }
        self.consumed = true;
        Ok(EffectRequest {
            event_id: self.event_id,
            scope: self.scope,
        })
    }
}

/// The typed request accepted by the host effect runner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EffectRequest {
    /// Source event ID for the receipt.
    pub event_id: EventId,
    /// Allowlisted effect scope.
    pub scope: Scope,
}

/// Why local authorization refused a request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Denied {
    /// Requested operation/resource is not allowed.
    Scope,
    /// Caller is not the paired owner.
    Owner,
    /// Policy epoch is stale.
    Epoch,
    /// Capability was already consumed.
    Consumed,
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn hostile_content_cannot_expand_scope() {
        let policy = LocalPolicy::read_memory(PeerId(1), Epoch(1), 7);
        let request = RemoteRequest {
            event_id: EventId(9),
            author: PeerId(99),
            scope: Scope {
                operation: Operation::ReadMemory,
                resource: 8,
            },
            content: vec![b'!'; 128],
        };
        assert_eq!(policy.authorize(request), Err(Denied::Scope));
    }

    #[test]
    fn capability_is_single_use_and_epoch_bound() {
        let policy = LocalPolicy::read_memory(PeerId(1), Epoch(1), 7);
        let request = RemoteRequest {
            event_id: EventId(9),
            author: PeerId(99),
            scope: Scope {
                operation: Operation::ReadMemory,
                resource: 7,
            },
            content: vec![],
        };
        let mut capability = policy.authorize(request).unwrap();
        assert_eq!(capability.consume(PeerId(2), Epoch(1)), Err(Denied::Owner));
        assert!(capability.consume(PeerId(1), Epoch(1)).is_ok());
        assert_eq!(
            capability.consume(PeerId(1), Epoch(1)),
            Err(Denied::Consumed)
        );
    }
}
