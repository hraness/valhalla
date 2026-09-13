#![no_std]
#![forbid(unsafe_code)]
//! Private bounded discovery over admitted social history. No output is authority.
extern crate alloc;

pub mod query;
pub mod snapshot;
pub mod state;
pub use query::*;
pub use snapshot::*;
pub use state::*;

/// Stable local failures, separate from untrusted text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Invalid count/size/value.
    Bounds,
    /// Malformed/noncanonical bytes or query.
    Encoding,
    /// Work or retained private-state capacity is exhausted.
    Budget,
    /// Snapshot, query, reader, policy or exact content changed.
    Stale,
    /// An evaluation clock moved backwards.
    Clock,
    /// Required signed evidence is absent or not currently admissible.
    Evidence,
}

/// Greatest requested output page.
pub const MAX_PAGE: usize = 64;
/// Largest retained private document/observation set, matching the archive ceiling.
pub const MAX_DOCUMENTS: usize = 4096;
/// Pure deterministic projection policy version.
pub const POLICY_VERSION: u16 = 1;
