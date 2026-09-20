//! Explicit local HTTP activation and durable route renewal.
use std::{ffi::OsString, io::Write, net::SocketAddr, path::PathBuf, sync::Arc};
use vhalla_public_peer::{Config, CorsOrigin, ManagedPeer, DEFAULT_LISTEN};
use vhalla_public_protocol::{response::hex, Endpoint};

pub const HELP: &str = "vhalla public serve BOOTSTRAP PIN64 KEY_DIR JOURNAL PEER_STATE HTTPS_ENDPOINT ALLOWED_ORIGIN [--listen LOOPBACK_IP:PORT] [--new-state] [--dev-origin]\n--new-state explicitly creates a new private advertisement state; omit to reconcile/reopen existing state. --dev-origin allows a literal loopback HTTP browser origin. Listener remains loopback HTTP; an explicitly operated HTTPS reverse proxy is required for public exposure.";

pub fn run(args: &[OsString]) -> Result<(), String> {
    if args.len() < 9 {
        return Err(HELP.into());
    }
    let text = |index: usize| {
        args[index]
            .to_str()
            .ok_or("arguments must be UTF-8".to_owned())
    };
    let pin = super::hex32(text(3)?)?;
    let mut listen: SocketAddr = DEFAULT_LISTEN
        .parse()
        .map_err(|_| "invalid default listener")?;
    let mut create = false;
    let mut dev = false;
    let mut seen_listen = false;
    let mut index = 9;
    while index < args.len() {
        match text(index)? {
            "--new-state" if !create => {
                create = true;
                index += 1;
            }
            "--dev-origin" if !dev => {
                dev = true;
                index += 1;
            }
            "--listen" if !seen_listen && index + 1 < args.len() => {
                listen = text(index + 1)?
                    .parse()
                    .map_err(|_| "invalid loopback listen address")?;
                seen_listen = true;
                index += 2;
            }
            _ => return Err(HELP.into()),
        }
    }
    let origin =
        if dev {
            let origin = text(8)?
                .strip_prefix("http://")
                .ok_or("--dev-origin requires http://LOOPBACK_IP:PORT")?;
            CorsOrigin::loopback_development(origin.parse().map_err(|_| {
                "development origin must use a literal loopback IP and nonzero port"
            })?)
        } else {
            CorsOrigin::https(text(8)?)
        }
        .map_err(|e| e.to_string())?;
    let state = PathBuf::from(&args[6]);
    let config = Config {
        bootstrap_file: PathBuf::from(&args[2]),
        bootstrap_pin: pin,
        identity_dir: PathBuf::from(&args[4]),
        journal_dir: PathBuf::from(&args[5]),
        advertisement_file: state.join("advertisement"),
        public_endpoint: Endpoint::parse(text(7)?)
            .map_err(|e| format!("public HTTPS endpoint: {e:?}"))?,
        allowed_origin: origin,
        listen,
    };
    let peer = Arc::new(
        if create {
            ManagedPeer::create(config, &state)
        } else {
            ManagedPeer::open(config, &state)
        }
        .map_err(|e| {
            format!("public serve startup: {e}; preserve publisher state on uncertainty")
        })?,
    );
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(|e| format!("runtime: {e}"))?;
    let outcome = runtime.block_on(async {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .map_err(|e| format!("SIGTERM handler: {e}"))?;
        let mut interrupt =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
                .map_err(|e| format!("SIGINT handler: {e}"))?;
        let bound = peer.clone().bind().await.map_err(|e| e.to_string())?;
        println!("network-id {}", hex(&peer.network_id()));
        println!("peer-key {}", hex(&peer.application_key()));
        println!(
            "advertisement-sequence {}",
            peer.advertisement_sequence().map_err(|e| e.to_string())?
        );
        println!(
            "advertisement-file {}",
            state.join("advertisement").display()
        );
        println!("listen {}", bound.local_addr().map_err(|e| e.to_string())?);
        println!("transport loopback-http-requires-explicit-https-proxy");
        std::io::stdout()
            .flush()
            .map_err(|e| format!("stdout: {e}"))?;
        bound
            .run(async {
                tokio::select! { _=terminate.recv()=>{}, _=interrupt.recv()=>{} }
            })
            .await
            .map_err(|e| {
                format!("public serve stopped: {e}; preserve state and reopen to reconcile")
            })?;
        println!("public-peer stopped");
        Ok(())
    });
    runtime.shutdown_timeout(std::time::Duration::from_secs(15));
    outcome
}
