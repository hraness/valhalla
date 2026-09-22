#![forbid(unsafe_code)]
#![warn(missing_docs)]
//! Native public peer adapter with explicit opt-in activity behind a TLS proxy.
//!
//! The HTTP listener only binds loopback. A successful response proves custody
//! of a full peer application key, not validator authority or global freshness.
//! Bootstrap trust and certified application replay remain client duties.
#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub use unix::{
    ActivityConfig, ActivityRoomConfig, BoundPeer, Config, ContinuityConfig, ContinuityRoomConfig,
    CorsOrigin, DiscoveryConfig, Error, ManagedBoundPeer, ManagedPeer, Peer,
    ACTIVITY_REPLAY_BUDGET, ADVERTISEMENT_LIFETIME_SECONDS, DEFAULT_LISTEN, MAX_ACTIVITY_ROOMS,
    MAX_CONNECTIONS, MAX_CONNECTIONS_PER_IP, MAX_DISCOVERY_PEERS,
};
