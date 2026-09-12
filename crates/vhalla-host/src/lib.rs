#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Typed host boundary for the steel thread.

use vhalla_core::Epoch;
use vhalla_policy::{EffectRequest, Operation};

/// A completed host receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Receipt {
    /// Event that caused the effect.
    pub event_id: vhalla_core::EventId,
    /// Effect that was executed.
    pub operation: Operation,
}

/// A host-side runner that accepts only typed effect requests.
pub trait EffectRunner {
    /// Execute one already-authorized request.
    fn execute(&mut self, request: EffectRequest) -> Receipt;
}

/// An in-memory runner used by the steel-thread integration test.
#[derive(Default)]
pub struct MemoryHost {
    reads: u64,
}

impl MemoryHost {
    /// Number of successful reads.
    #[must_use]
    pub const fn reads(&self) -> u64 {
        self.reads
    }
}

impl EffectRunner for MemoryHost {
    fn execute(&mut self, request: EffectRequest) -> Receipt {
        self.reads += 1;
        Receipt {
            event_id: request.event_id,
            operation: request.scope.operation,
        }
    }
}

/// Execute a capability through the host boundary using the current owner/epoch.
pub fn execute(
    host: &mut impl EffectRunner,
    capability: &mut vhalla_policy::AuthorizedEffect,
    owner: vhalla_core::PeerId,
    epoch: Epoch,
) -> Result<Receipt, vhalla_policy::Denied> {
    let request = capability.consume(owner, epoch)?;
    Ok(host.execute(request))
}
