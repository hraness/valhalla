//! Native encrypted private-room persistence and fixed-room agent capabilities.
#![forbid(unsafe_code)]
#![cfg(unix)]
pub mod agent;
pub mod bridge;
pub mod private_rooms;
