//! Explicit pinned-bootstrap tools; public serving is a separate activation.
use std::{
    collections::BTreeMap,
    ffi::OsString,
    fs::OpenOptions,
    io::{Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::Path,
};
use vhalla_public_client::{Bootstrap, Validator, ValidatorActivation, MAX_BOOTSTRAP_BYTES};
use vhalla_rooms_app::ServiceConfig;
use vhalla_rooms_consensus::Genesis;

#[path = "public_serve.rs"]
mod serve;

#[path = "public_discovery.rs"]
mod discovery;

#[path = "public_activity.rs"]
mod activity;

pub const HELP: &str = "vhalla public bootstrap-export CONFIG GENESIS_SOCIAL NEW_FILE\nvhalla public bootstrap-check FILE FULL_PIN64\nvhalla public serve BOOTSTRAP PIN64 KEY_DIR JOURNAL PEER_STATE HTTPS_ENDPOINT ALLOWED_ORIGIN [--listen LOOPBACK_IP:PORT] [--new-state] [--dev-origin]\nNative local authoring and bounded outbox export: vhalla public activity (see command help).\nDiscovery serving/selected-seed registration: vhalla public discovery-serve (see command help).\nServe creates no identity and remains loopback HTTP; public TLS requires an explicit reverse proxy. New advertisement state requires --new-state.\nExport binds the exact signed genesis archive and validator schedule. Compare the full pin through an independent trusted channel; it is not a server's authority claim.";

fn bytes(path: &Path, max: usize) -> Result<Vec<u8>, String> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY)
        .open(path)
        .map_err(|e| format!("open public input: {e}"))?;
    let metadata = file
        .metadata()
        .map_err(|e| format!("public input metadata: {e}"))?;
    if !metadata.is_file() || metadata.len() > max as u64 {
        return Err("public input must be a bounded regular file".into());
    }
    let mut raw = Vec::with_capacity(metadata.len() as usize);
    file.take(max as u64 + 1)
        .read_to_end(&mut raw)
        .map_err(|e| format!("read public input: {e}"))?;
    if raw.len() > max {
        return Err("public input grew beyond its limit".into());
    }
    Ok(raw)
}
fn hex32(text: &str) -> Result<[u8; 32], String> {
    if text.len() != 64
        || !text
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err("expected 64 lowercase hexadecimal characters".into());
    }
    let mut out = [0; 32];
    for (i, pair) in text.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        out[i] = u8::from_str_radix(std::str::from_utf8(pair).map_err(|_| "invalid hex")?, 16)
            .map_err(|_| "invalid hex")?;
    }
    Ok(out)
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn report(bootstrap: &Bootstrap) {
    println!("bootstrap-pin {}", hex(&bootstrap.pin()));
    println!("network-id {}", hex(&bootstrap.network_id()));
    println!(
        "genesis-social-root {}",
        hex(bootstrap.genesis().archive.root().as_bytes())
    );
    println!("trust-status requires-independent-pin-verification");
}
pub fn run(args: Vec<OsString>) -> Result<(), String> {
    match args.get(1).and_then(|s| s.to_str()) {
        Some("serve") => serve::run(&args),
        Some("activity") => activity::run(&args),
        Some("discovery-serve") => discovery::run(&args),
        // Private self-exec protocol: bounded resolver process, no network dial.
        Some("discovery-resolve") => discovery::resolve_child(&args),
        Some("bootstrap-export") if args.len() == 5 => {
            let raw = bytes(Path::new(&args[2]), 64 * 1024)?;
            let config = ServiceConfig::parse(&raw).map_err(|e| format!("configuration: {e}"))?;
            let realm = config.realm_id().map_err(|e| format!("realm: {e}"))?;
            let limits = config
                .archive_limits()
                .check()
                .map_err(|_| "invalid archive limits")?;
            let archive = vhalla_social_store::read_archive(Path::new(&args[3]), realm, limits)
                .map_err(|e| format!("genesis archive: {e:?}"))?;
            let genesis = Genesis {
                directory: vhalla_rooms::DirectoryId::from_bytes(hex32(&config.directory)?),
                realm,
                policy: config.directory_policy(),
                eligible: config
                    .eligible
                    .iter()
                    .map(|id| hex32(id).map(vhalla_social::OwnerId::from_bytes))
                    .collect::<Result<_, _>>()?,
                limits,
                archive,
            };
            let mut sets: BTreeMap<u64, Vec<Validator>> = BTreeMap::new();
            for validator in config.validators {
                sets.entry(validator.from).or_default().push(Validator {
                    public_key: hex32(&validator.key)?,
                    power: validator.power,
                });
            }
            let schedule = sets
                .into_iter()
                .map(|(from, validators)| ValidatorActivation { from, validators })
                .collect();
            let bootstrap = Bootstrap::from_genesis(genesis, schedule)
                .map_err(|e| format!("invalid bootstrap: {e:?}"))?;
            let path = Path::new(&args[4]);
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o644)
                .open(path)
                .map_err(|e| format!("create new bootstrap (never overwrites): {e}"))?;
            file.write_all(&bootstrap.encode()).and_then(|_| file.sync_all()).map_err(|e| format!("bootstrap publication uncertain: {e}; preserve the file and inspect before retry"))?;
            let parent = path
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new("."));
            std::fs::File::open(parent)
                .and_then(|p| p.sync_all())
                .map_err(|e| format!("bootstrap directory publication uncertain: {e}"))?;
            report(&bootstrap);
            Ok(())
        }
        Some("bootstrap-check") if args.len() == 4 => {
            let pin = hex32(args[3].to_str().ok_or("invalid bootstrap pin")?)?;
            let raw = bytes(Path::new(&args[2]), MAX_BOOTSTRAP_BYTES)?;
            let bootstrap =
                Bootstrap::decode(&raw, pin).map_err(|e| format!("bootstrap rejected: {e:?}"))?;
            report(&bootstrap);
            Ok(())
        }
        _ => Err(HELP.into()),
    }
}
