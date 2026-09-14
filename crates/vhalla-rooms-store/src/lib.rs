#![forbid(unsafe_code)]
#![warn(missing_docs)]
//! Private-file room registry persistence; this is not hostile-host rollback
//! protection.
//!
//! The Unix adapter requires an owner-controlled directory and ancestors on a
//! local filesystem supporting exclusive locks, atomic rename, and file and
//! directory synchronization. It publishes a complete canonical registry
//! snapshot only after durable intent reconciliation. The retained snapshot
//! carries every admitted signed record — the durable room manifests and
//! tombstones — plus a checksum that is integrity evidence, never an external
//! freshness proof. Registry revision ordering, not snapshot bytes, is the
//! lineage bound: a stale or divergent candidate is rejected, never silently
//! reconciled. Other platforms have no filesystem activation in this version.

#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub use unix::{Error, Pin, Publication, Store, PIN_BYTES};
