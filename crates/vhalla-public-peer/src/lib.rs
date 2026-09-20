#![forbid(unsafe_code)]
#![warn(missing_docs)]
//! Native read-only public peer adapter behind an explicitly operated TLS proxy.
//!
//! The HTTP listener only binds loopback. A successful response proves custody
//! of a full peer application key, not validator authority or global freshness.
//! Bootstrap trust and certified application replay remain client duties.
#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub use unix::{
    ActivityConfig, ActivityRoomConfig, BoundPeer, Config, CorsOrigin, DiscoveryConfig, Error,
    ManagedBoundPeer, ManagedPeer, Peer, ACTIVITY_REPLAY_BUDGET, ADVERTISEMENT_LIFETIME_SECONDS,
    DEFAULT_LISTEN, MAX_ACTIVITY_ROOMS, MAX_CONNECTIONS, MAX_CONNECTIONS_PER_IP,
    MAX_DISCOVERY_PEERS,
};
