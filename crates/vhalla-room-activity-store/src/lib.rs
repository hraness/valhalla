#![forbid(unsafe_code)]
#![warn(missing_docs)]
//! Owner-private Unix persistence for public room activity, separate from the
//! bounded social archive. Stored receipts prove neither consensus nor global
//! admission, current permission, delivery, or hostile-host rollback resistance.
//!
//! The caller must hold its certified-registry integration lock throughout new
//! admission and supply the current pinned registry digest. This crate holds
//! only its own filesystem lock; it cannot establish registry provenance.
//! A durable intent freezes that checked local decision. Explicit recovery
//! finishes the exact old decision even if the room has since closed.

#[cfg(unix)]
mod codec;
#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub use codec::{Limits, Pin, PIN_BYTES};
#[cfg(unix)]
pub use unix::{Error, Page, Store, StoredEvent, MAX_PAGE};

/// Explicitly initialized continuity-capable activity storage.
#[cfg(unix)]
pub mod continuity;

#[cfg(all(unix, test))]
#[path = "../../vhalla-rooms/tests/common/mod.rs"]
mod common;
