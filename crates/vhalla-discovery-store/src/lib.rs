#![forbid(unsafe_code)]
//! Separate private discovery/attention persistence. Nothing in this directory is
//! included in public social snapshots. Checksums provide no rollback protection.

#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub use unix::{Error, Pin, PrivateState, Publication, Store};
