//! Explicit local HTTP activation and durable route renewal.
use std::{ffi::OsString, io::Write, net::SocketAddr, path::PathBuf, sync::Arc};
use vhalla_public_client::{Bootstrap, CertifiedClient, MAX_BOOTSTRAP_BYTES};
use vhalla_public_peer::{
    ActivityConfig, ActivityRoomConfig, Config, ContinuityConfig, ContinuityRoomConfig, CorsOrigin,
    ManagedPeer, DEFAULT_LISTEN, MAX_ACTIVITY_ROOMS,
};
use vhalla_public_protocol::{response::hex, Endpoint};
use vhalla_room_activity::RoomScope;
use vhalla_room_activity_store::continuity::{ContinuityLimits, ContinuityStore};
use vhalla_room_activity_store::{Limits, Store};
use vhalla_rooms::RoomGenesisId;

pub const HELP: &str = "vhalla public serve BOOTSTRAP PIN64 KEY_DIR JOURNAL PEER_STATE HTTPS_ENDPOINT ALLOWED_ORIGIN [--listen LOOPBACK_IP:PORT] [--new-state] [--dev-origin] [--activity-store ROOM64 STORE MAX_EVENTS MAX_HISTORY_BYTES]... [--continuity-store ROOM64 STORE MAX_EVENTS MAX_HISTORY_BYTES MAX_STAGE_SLOTS MAX_STAGE_EVENTS MAX_STAGE_BYTES TTL_SECONDS]...\n--continuity-store explicitly selects new VHPM2 continuity publishing and cannot mix with --activity-store. Existing mode and every limit must match on restart.\n--activity-store explicitly enables public activity for existing stores (max32). Exact entries are immutable across restart; default is READ-only.\n--new-state explicitly creates a new private advertisement state; omit to reconcile/reopen existing state. --dev-origin allows a literal loopback HTTP browser origin. Listener remains loopback HTTP; an explicitly operated HTTPS reverse proxy is required for public exposure.";

pub const INIT_HELP: &str = "vhalla public activity-store-init BOOTSTRAP PIN64 ROOM64 NEW_STORE MAX_EVENTS MAX_HISTORY_BYTES\nCreates one NEW private local store scoped to the independently pinned network and selected full room ID. Does not start a listener, verify that the room exists, enable its public policy, or grant posting. Existing paths and noncanonical/nonpositive limits are refused.";
pub const CONTINUITY_INIT_HELP: &str = "vhalla public continuity-store-init BOOTSTRAP PIN64 ROOM64 NEW_STORE MAX_EVENTS MAX_HISTORY_BYTES MAX_STAGE_SLOTS MAX_STAGE_EVENTS MAX_STAGE_BYTES TTL_SECONDS\nCreates an explicit new VHCF2 store; never migrates or resets a v1 store. Every limit is immutable. Slots 1..64, staged events 32..4096, staged bytes 1..33554432, TTL 60..86400 seconds. Full-capacity upload needs at least six rate windows; choose and qualify a sufficiently long fixed TTL. No listener, identity creation or policy grant.";

fn continuity_limits(args: &[OsString], start: usize) -> Result<ContinuityLimits, String> {
    let fields = args.get(start..start + 6).ok_or(CONTINUITY_INIT_HELP)?;
    let value = |n: usize| positive(fields[n].to_str().ok_or("limits must be UTF-8")?);
    let limits = ContinuityLimits {
        history: Limits {
            max_events: value(0)?,
            max_history_bytes: value(1)?,
        },
        max_stage_slots: u16::try_from(value(2)?).map_err(|_| "stage slots exceed u16")?,
        max_stage_events: value(3)?,
        max_stage_bytes: value(4)?,
        stage_ttl_seconds: value(5)?,
    };
    // Reject invalid immutable settings before opening identity/publisher custody.
    if limits.max_stage_slots > 64
        || !(32..=4096).contains(&limits.max_stage_events)
        || limits.max_stage_bytes > 32 * 1024 * 1024
        || !(60..=86400).contains(&limits.stage_ttl_seconds)
    {
        return Err(CONTINUITY_INIT_HELP.into());
    }
    Ok(limits)
}

pub fn init_continuity_store(args: &[OsString]) -> Result<(), String> {
    if args.len() != 12 {
        return Err(CONTINUITY_INIT_HELP.into());
    }
    let text = |n: usize| args[n].to_str().ok_or("arguments must be UTF-8");
    let pin = super::hex32(text(3)?)?;
    let room = RoomGenesisId::from_bytes(super::hex32(text(4)?)?);
    let limits = continuity_limits(args, 6)?;
    let bootstrap = Bootstrap::decode(
        &super::bytes(std::path::Path::new(&args[2]), MAX_BOOTSTRAP_BYTES)?,
        pin,
    )
    .map_err(|e| format!("independently pinned bootstrap: {e:?}"))?;
    let client =
        CertifiedClient::new(bootstrap, pin).map_err(|e| format!("network genesis: {e:?}"))?;
    let scope = RoomScope {
        network: client.network_id(),
        realm: client.registry().realm(),
        directory: client.registry().directory(),
        room,
    };
    let store = ContinuityStore::create(std::path::Path::new(&args[5]), scope, limits)
        .map_err(|e| format!("new continuity store: {e:?}; preserve partial state, never reset"))?;
    println!("network-id {}", hex(&scope.network));
    println!("room-id {}", hex(scope.room.as_bytes()));
    println!("continuity-format VHCF2");
    println!("terminal-count {}", store.pin().feed_count());
    println!("authority local-storage-only-no-room-policy-grant");
    Ok(())
}
fn positive(raw: &str) -> Result<u64, String> {
    let value = raw
        .parse::<u64>()
        .map_err(|_| "limits must be canonical positive u64 integers")?;
    if value == 0 || value.to_string() != raw {
        return Err("limits must be canonical positive u64 integers".into());
    }
    Ok(value)
}
pub fn init_store(args: &[OsString]) -> Result<(), String> {
    if args.len() != 8 {
        return Err(INIT_HELP.into());
    }
    let text = |index: usize| args[index].to_str().ok_or("arguments must be UTF-8");
    let pin = super::hex32(text(3)?)?;
    let room = RoomGenesisId::from_bytes(super::hex32(text(4)?)?);
    let limits = Limits {
        max_events: positive(text(6)?)?,
        max_history_bytes: positive(text(7)?)?,
    };
    let bootstrap = Bootstrap::decode(
        &super::bytes(std::path::Path::new(&args[2]), MAX_BOOTSTRAP_BYTES)?,
        pin,
    )
    .map_err(|e| format!("independently pinned bootstrap: {e:?}"))?;
    let client =
        CertifiedClient::new(bootstrap, pin).map_err(|e| format!("network genesis: {e:?}"))?;
    let scope = RoomScope {
        network: client.network_id(),
        realm: client.registry().realm(),
        directory: client.registry().directory(),
        room,
    };
    let path = std::path::Path::new(&args[5]);
    let store = Store::create(path, scope, limits).map_err(|e| {
        format!("new activity store: {e:?}; preserve any partial state, never reset")
    })?;
    println!("network-id {}", hex(&scope.network));
    println!("room-id {}", hex(scope.room.as_bytes()));
    println!("activity-store {}", path.display());
    println!("activity-count {}", store.pin().count());
    println!("authority local-storage-only-no-room-policy-grant");
    Ok(())
}

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
    let mut rooms = Vec::<ActivityRoomConfig>::new();
    let mut continuity_rooms = Vec::<ContinuityRoomConfig>::new();
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
            "--activity-store"
                if index + 4 < args.len()
                    && rooms.len() < MAX_ACTIVITY_ROOMS
                    && continuity_rooms.is_empty() =>
            {
                let room = RoomGenesisId::from_bytes(super::hex32(text(index + 1)?)?);
                if rooms.iter().any(|entry| entry.room == room) {
                    return Err("duplicate activity room".into());
                }
                rooms.push(ActivityRoomConfig {
                    room,
                    directory: PathBuf::from(&args[index + 2]),
                    limits: Limits {
                        max_events: positive(text(index + 3)?)?,
                        max_history_bytes: positive(text(index + 4)?)?,
                    },
                });
                index += 5;
            }
            "--continuity-store"
                if index + 8 < args.len()
                    && continuity_rooms.len() < MAX_ACTIVITY_ROOMS
                    && rooms.is_empty() =>
            {
                let room = RoomGenesisId::from_bytes(super::hex32(text(index + 1)?)?);
                if continuity_rooms.iter().any(|entry| entry.room == room) {
                    return Err("duplicate continuity room".into());
                }
                continuity_rooms.push(ContinuityRoomConfig {
                    room,
                    directory: PathBuf::from(&args[index + 2]),
                    limits: continuity_limits(args, index + 3)?,
                });
                index += 9;
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
    let continuity = !continuity_rooms.is_empty();
    let publishing = !rooms.is_empty() || continuity;
    let peer = Arc::new(
        if continuity {
            let selected = ContinuityConfig {
                rooms: continuity_rooms,
            };
            if create {
                ManagedPeer::create_with_continuity(config, &state, selected)
            } else {
                ManagedPeer::open_with_continuity(config, &state, selected)
            }
        } else {
            match (create, publishing) {
                (true, false) => ManagedPeer::create(config, &state),
                (false, false) => ManagedPeer::open(config, &state),
                (true, true) => {
                    ManagedPeer::create_with_activity(config, &state, ActivityConfig { rooms })
                }
                (false, true) => {
                    ManagedPeer::open_with_activity(config, &state, ActivityConfig { rooms })
                }
            }
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
        println!(
            "activity-mode {}",
            if continuity {
                "public-continuity"
            } else if publishing {
                "public-publish"
            } else {
                "read-only"
            }
        );
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
