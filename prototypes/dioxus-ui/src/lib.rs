#![forbid(unsafe_code)]
//! Shared Dioxus screen spike. This is not a production client or durable store.

mod action_guard;
pub mod fixture;
pub mod services;
pub mod ui;

pub use ui::{
    fixture_app, fixture_config, fixture_resources, portrait_resource, App, AppConfig,
    ReaderChoice, CLOSED_STYLE_URI, STYLE, STYLE_BYTES,
};
