#![forbid(unsafe_code)]
#![warn(missing_docs)]
//! Private-file social persistence; this is not hostile-host rollback protection.
//!
//! The Unix adapter requires an owner-controlled directory and ancestors on a
//! local filesystem supporting exclusive locks, atomic rename, and file/directory
//! synchronization. It publishes full signed evidence only after durable intent
//! reconciliation. A checksum is integrity evidence, never an external freshness
//! proof. Other platforms have no filesystem activation in this version.

#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub use unix::{Error, Pin, Publication, Store, PIN_BYTES};
