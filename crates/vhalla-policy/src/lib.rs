#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Explicit local grants over immutable, authenticated remote requests.
//!
//! Constructors configure trusted local policy. They are not a sandbox against
//! hostile code in the same process. A verified peer message is evidence only;
//! the local policy must also grant its full signing key, context, and scope.

use vhalla_core::EventId;
pub use vhalla_crypto::VerificationContext;
use vhalla_crypto::VerifiedEnvelope;

/// Reserved kind for the first bounded in-memory read request.
pub const KIND_READ_MEMORY_REQUEST: u8 = 2;

/// The only operation exposed by the first steel thread.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operation {
    /// A bounded in-memory read used by the demonstration host.
    ReadMemory,
}

/// Locally selected operation and resource; this value is not authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Scope {
    /// Requested operation.
    pub operation: Operation,
    /// Host-defined resource identifier.
    pub resource: u32,
}

/// An inert request that retains the consumed signature and replay evidence.
/// Remote bytes cannot fabricate this type or change its authenticated fields.
///
/// ```compile_fail
/// use vhalla_policy::{RemoteRequest, Scope};
/// fn fabricate(scope: Scope) -> RemoteRequest { RemoteRequest { scope } }
/// ```
#[derive(Debug)]
pub struct RemoteRequest {
    verified: VerifiedEnvelope,
    scope: Scope,
}

impl RemoteRequest {
    /// Consume verified evidence and select a typed scope locally. Ordinary
    /// chat and unknown message kinds cannot enter the effect-request path.
    pub fn from_verified(verified: VerifiedEnvelope, scope: Scope) -> Result<Self, Denied> {
        if verified.envelope().kind() != KIND_READ_MEMORY_REQUEST {
            return Err(Denied::Kind);
        }
        Ok(Self { verified, scope })
    }

    /// Foreign content remains immutable data, never policy instructions.
    #[must_use]
    pub fn content(&self) -> &[u8] {
        self.verified.envelope().body()
    }
}

/// One locally configured full-key grant in one host/session/policy context.
///
/// Policy replacement belongs to the host. A policy value cannot revoke
/// capabilities that have already been passed to a different execution system.
#[derive(Debug, Eq, PartialEq)]
pub struct LocalPolicy {
    context: VerificationContext,
    requester: [u8; 32],
    scope: Scope,
}

impl LocalPolicy {
    /// Grant one in-memory resource to exactly this signing key and context.
    #[must_use]
    pub const fn read_memory(
        context: VerificationContext,
        requester: [u8; 32],
        resource: u32,
    ) -> Self {
        Self {
            context,
            requester,
            scope: Scope {
                operation: Operation::ReadMemory,
                resource,
            },
        }
    }

    /// Context the actual host must retain and compare during execution.
    #[must_use]
    pub const fn context(&self) -> VerificationContext {
        self.context
    }

    /// Explicit locally granted scope.
    #[must_use]
    pub const fn scope(&self) -> Scope {
        self.scope
    }

    /// Full signing key of the locally granted requester.
    #[must_use]
    pub const fn requester(&self) -> &[u8; 32] {
        &self.requester
    }

    /// Turn verified data into a move-only capability only for this exact grant.
    pub fn authorize(&self, request: RemoteRequest) -> Result<AuthorizedEffect, Denied> {
        self.check_grant(
            request.verified.context(),
            request.verified.signer_key(),
            request.scope,
        )?;
        Ok(AuthorizedEffect {
            event_id: request.verified.envelope().event(),
            context: request.verified.context(),
            requester: *request.verified.signer_key(),
            scope: request.scope,
            expires_at: request.verified.expires_at(),
        })
    }

    /// Check a prepared capability against the host's current policy and clock.
    /// This read-only check does not execute or consume the capability. The host
    /// must accept it by value and perform this check at the actual effect.
    pub fn validate_effect(&self, effect: &AuthorizedEffect, now: u64) -> Result<(), Denied> {
        self.check_grant(effect.context, &effect.requester, effect.scope)?;
        if now > effect.expires_at {
            return Err(Denied::Expired);
        }
        Ok(())
    }

    fn check_grant(
        &self,
        context: VerificationContext,
        requester: &[u8; 32],
        scope: Scope,
    ) -> Result<(), Denied> {
        if context.audience != self.context.audience {
            return Err(Denied::Owner);
        }
        if context.epoch != self.context.epoch {
            return Err(Denied::Epoch);
        }
        if context != self.context {
            return Err(Denied::Context);
        }
        if requester != &self.requester {
            return Err(Denied::Requester);
        }
        if scope != self.scope {
            return Err(Denied::Scope);
        }
        Ok(())
    }
}

/// Sealed move-only capability. The execution boundary consumes this value.
///
/// ```compile_fail
/// use vhalla_policy::AuthorizedEffect;
/// fn duplicate(effect: AuthorizedEffect) { let _other = effect.clone(); }
/// ```
///
/// ```compile_fail
/// use vhalla_policy::{AuthorizedEffect, Scope};
/// fn change_scope(effect: &mut AuthorizedEffect, scope: Scope) { effect.scope = scope; }
/// ```
#[derive(Debug)]
pub struct AuthorizedEffect {
    event_id: EventId,
    context: VerificationContext,
    requester: [u8; 32],
    scope: Scope,
    expires_at: u64,
}

impl AuthorizedEffect {
    /// Event named by the authenticated request; a copy is ordinary data.
    #[must_use]
    pub const fn event_id(&self) -> EventId {
        self.event_id
    }
    /// Locally authorized scope; a copy cannot alter the capability.
    #[must_use]
    pub const fn scope(&self) -> Scope {
        self.scope
    }
}

/// Why local authorization or current-policy validation refused a request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Denied {
    /// Message kind is not a typed read request.
    Kind,
    /// Operation or resource has no local grant.
    Scope,
    /// Audience differs from this host's owner identity.
    Owner,
    /// Policy epoch differs or a replacement does not advance it.
    Epoch,
    /// Realm, room, or session differs from the local context.
    Context,
    /// The complete signing key has no local grant.
    Requester,
    /// The signed request expired before actual execution.
    Expired,
}
