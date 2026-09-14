//! The `rooms tui` command: a terminal companion over a node's journal.
//!
//! `vhalla rooms tui SOCIAL_STORE REPLICA_HOME REALM NODE_HOME --config
//! FILE` opens a `vhalla_rooms_app::Service` replica against the node's
//! journal and drives `vhalla_rooms_tui`. The companion holds no node or
//! store authority: it reads committed bundles, and its submissions are
//! ordinary intake drops — signed in this process from explicit identity
//! paths the form asks for, exactly like `rooms create`.

use std::path::Path;

use vhalla_rooms_app::{Service, ServiceConfig};
use vhalla_rooms_tui::{run as tui_run, App};

use crate::rooms::Args;

/// Opens the replica and runs the terminal loop until the user quits.
pub fn run(args: &Args) -> Result<(), String> {
    let config_path = args.config.as_deref().ok_or("tui needs --config FILE")?;
    let node_home = args
        .value(0)
        .ok_or("tui takes NODE_HOME; see vhalla rooms --help")?;
    let raw = std::fs::read(config_path).map_err(|e| format!("config: {e}"))?;
    let config = ServiceConfig::parse(&raw).map_err(|e| e.to_string())?;
    if config.realm_id().map_err(|e| e.to_string())? != args.realm {
        return Err("config realm does not match the REALM argument".into());
    }
    let mut service = Service::open(
        Path::new(&args.social_store),
        Path::new(node_home),
        Path::new(&args.rooms_store),
        &config,
    )
    .map_err(|e| e.to_string())?;
    let mut app = App::new(args.now());
    tui_run(&mut app, &mut service).map_err(|e| e.to_string())
}
