//! Native encrypted private-room persistence and fixed-room agent capabilities.
#![forbid(unsafe_code)]
pub mod agent;
#[cfg(feature = "client")]
pub mod archive;
pub mod bridge;
#[cfg(feature = "client")]
pub mod client;
#[cfg(feature = "habitat-link")]
pub mod habitat_link;
pub mod private_rooms;
pub mod relay;
