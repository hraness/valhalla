#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! In-memory execution under host-owned current policy.
//!
//! There is deliberately no general runner trait, raw effect request, or OS
//! effect. Trusted local code configures the policy and supplies clock readings.
//! Rust ownership prevents ordinary capability duplication; it does not isolate
//! hostile code or protect policy/clock storage in a compromised process.

use vhalla_core::EventId;
use vhalla_policy::{AuthorizedEffect, Denied, LocalPolicy, Operation, RemoteRequest};

/// Local observational receipt; this plain value is not signed execution proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Receipt {
    /// Event that caused the effect.
    pub event_id: EventId,
    /// Effect that was executed.
    pub operation: Operation,
}

/// Bounded host failures; a rejected capability is consumed without execution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostError {
    /// Current policy or execution-time expiry rejected the capability.
    Denied(Denied),
    /// The demonstration counter cannot advance without wrapping.
    CounterOverflow,
}

impl From<Denied> for HostError {
    fn from(error: Denied) -> Self {
        Self::Denied(error)
    }
}

/// A host that owns its current policy and accepts only move-only capabilities.
///
/// ```compile_fail
/// use vhalla_host::MemoryHost;
/// use vhalla_policy::AuthorizedEffect;
/// fn replay(host: &mut MemoryHost, effect: AuthorizedEffect) {
///     let _ = host.execute(effect, 50);
///     let _ = host.execute(effect, 50);
/// }
/// ```
///
/// The old fabricable effect-request and unguarded runner interface are absent.
///
/// ```compile_fail
/// use vhalla_host::EffectRunner;
/// use vhalla_policy::EffectRequest;
/// ```
#[derive(Debug)]
pub struct MemoryHost {
    policy: LocalPolicy,
    reads: u64,
}

impl MemoryHost {
    /// Install explicit trusted local policy before accepting remote requests.
    #[must_use]
    pub const fn new(policy: LocalPolicy) -> Self {
        Self { policy, reads: 0 }
    }

    /// Mint a capability only through this host's current local grant.
    pub fn authorize(&self, request: RemoteRequest) -> Result<AuthorizedEffect, Denied> {
        self.policy.authorize(request)
    }

    /// Consume a capability and check the actual host's current grant and the
    /// caller's trusted clock reading immediately before the in-memory effect.
    pub fn execute(&mut self, effect: AuthorizedEffect, now: u64) -> Result<Receipt, HostError> {
        self.policy.validate_effect(&effect, now)?;
        let next_reads = self
            .reads
            .checked_add(1)
            .ok_or(HostError::CounterOverflow)?;
        self.reads = next_reads;
        Ok(Receipt {
            event_id: effect.event_id(),
            operation: effect.scope().operation,
        })
    }

    /// Replace a local grant only at a strictly newer epoch in the same owner,
    /// realm, room, and session. Old prepared capabilities then fail at execute.
    /// A rejected replacement preserves the current policy and counter.
    pub fn replace_policy(&mut self, next: LocalPolicy) -> Result<(), Denied> {
        let current = self.policy.context();
        let future = next.context();
        if future.audience != current.audience {
            return Err(Denied::Owner);
        }
        if future.realm != current.realm
            || future.room != current.room
            || future.session != current.session
        {
            return Err(Denied::Context);
        }
        if future.epoch <= current.epoch {
            return Err(Denied::Epoch);
        }
        self.policy = next;
        Ok(())
    }

    /// Number of successful in-memory reads.
    #[must_use]
    pub const fn reads(&self) -> u64 {
        self.reads
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vhalla_core::{Epoch, PeerId, RealmId, RoomId, Sequence};
    use vhalla_crypto::{
        peer_id_from_seed, sign, verifying_key_from_seed, ReplayWindow, SessionId,
        VerificationContext,
    };
    use vhalla_policy::{Scope, KIND_READ_MEMORY_REQUEST};
    use vhalla_wire::Envelope;

    #[test]
    fn exhausted_counter_rejects_without_wrapping_or_issuing_receipt() {
        let context = VerificationContext {
            audience: PeerId(1),
            realm: RealmId(2),
            room: RoomId(3),
            epoch: Epoch(1),
            session: SessionId(4),
        };
        let seed = [7; 32];
        let key = verifying_key_from_seed(seed);
        let envelope = Envelope::new(
            KIND_READ_MEMORY_REQUEST,
            peer_id_from_seed(seed),
            context.realm,
            context.room,
            EventId(9),
            Sequence(1),
            b"read",
        )
        .unwrap();
        let signed = sign(
            envelope,
            context.audience,
            context.epoch,
            context.session,
            100,
            seed,
        )
        .unwrap();
        let verified = ReplayWindow::new(context, 1)
            .unwrap()
            .verify_and_accept(signed, &key, 50)
            .unwrap();
        let request = RemoteRequest::from_verified(
            verified,
            Scope {
                operation: Operation::ReadMemory,
                resource: 11,
            },
        )
        .unwrap();
        let mut host = MemoryHost::new(LocalPolicy::read_memory(context, key.to_bytes(), 11));
        let capability = host.authorize(request).unwrap();
        host.reads = u64::MAX;
        assert_eq!(
            host.execute(capability, 75),
            Err(HostError::CounterOverflow)
        );
        assert_eq!(host.reads(), u64::MAX);
    }
}
