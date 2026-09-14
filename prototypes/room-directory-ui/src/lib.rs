#![forbid(unsafe_code)]
//! Shared Dioxus screen spike for the room-directory companion. This is
//! not a production client — it renders `vhalla_rooms_app` projections
//! and drops signed bodies through the service boundary only.

pub mod services;
pub mod ui;

pub use services::{FixtureServices, RoomServices};
pub use ui::{fixture_app, App, Id, Route, CLOSED_STYLE_URI, STYLE, STYLE_BYTES};
