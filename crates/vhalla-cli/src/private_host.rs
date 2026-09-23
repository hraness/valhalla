//! Explicit local opaque-relay hosting. No account or room custody lives here.
mod config;
pub(crate) mod events;
pub(crate) mod launchd;

use config::{Config, Loaded};
use std::{
    ffi::OsString,
    net::{IpAddr, SocketAddr, TcpListener},
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};
use vhalla_private_native::relay::{
    net::RelayToken,
    tls::{self, Credential, Permissions, Service, ServiceLimits},
    FileStore, Limits, RelayNamespace,
};

pub(crate) const HELP: &str = "vhalla private-host init NEW_HOME [--listen LOOPBACK_IP:PORT] [--tls-name NAME] [--executable ABSOLUTE_BINARY] [--leaf-days 1-3650]\nvhalla private-host serve|install|uninstall HOME\nvhalla private-host status HOME [--probe]\nvhalla private-host add-credential|rotate|renew HOME\nvhalla private-host tailcat-plist HOME --binary ABSOLUTE_TAILCAT --key ABSOLUTE_SAVED_KEY --out NEW_PRIVATE_PLIST\nOwner-private local TLS mailbox, two or more distinct client credentials, explicit macOS LaunchAgent lifecycle. No account keys, automatic update, public listener, or cloud provisioning.";
const REFUSED: &str = "local host refused; preserve the exact home, configuration, certificates and mailbox; never reset retained custody";
/// Status marks the leaf for explicit operator renewal inside this window.
const RENEWAL_WARNING_SECS: i64 = 30 * 86400;

pub(crate) fn run(args: &[OsString]) -> Result<(), String> {
    if args.len() < 3 || args[0] != "private-host" {
        return Err(HELP.into());
    }
    let home = Path::new(&args[2]);
    match args[1].to_str() {
        Some("init") => {
            let mut listen: SocketAddr = "127.0.0.1:9473".parse().map_err(|_| REFUSED)?;
            let mut name = "relay.valhalla.invalid".to_owned();
            let mut executable = std::env::current_exe().map_err(|_| REFUSED)?;
            let mut leaf_days = 365i64;
            let mut seen = std::collections::BTreeSet::new();
            if !(args.len() - 3).is_multiple_of(2) {
                return Err(HELP.into());
            }
            for pair in args[3..].as_chunks::<2>().0.iter() {
                let flag = pair[0].to_str().ok_or(HELP)?;
                if !seen.insert(flag) {
                    return Err(HELP.into());
                }
                match flag {
                    "--listen" => {
                        listen = pair[1].to_str().ok_or(HELP)?.parse().map_err(|_| HELP)?
                    }
                    "--tls-name" => name = pair[1].to_str().ok_or(HELP)?.to_owned(),
                    "--executable" => {
                        executable = pair[1].clone().into();
                        if !executable.is_absolute() {
                            return Err(HELP.into());
                        }
                    }
                    "--leaf-days" => {
                        leaf_days = pair[1].to_str().ok_or(HELP)?.parse().map_err(|_| HELP)?;
                        if !(1..=3650).contains(&leaf_days) {
                            return Err(HELP.into());
                        }
                    }
                    _ => return Err(HELP.into()),
                }
            }
            if !listen.ip().is_loopback() || listen.port() == 0 {
                return Err("local host requires an explicit nonzero loopback endpoint; expose it only through a separately reviewed encrypted overlay".into());
            }
            let loaded = config::initialize_with_leaf_lifetime(
                home,
                listen,
                &name,
                &executable,
                time::Duration::days(leaf_days),
            )?;
            println!(
                "{}",
                serde_json::json!({"status":"initialized","home":loaded.home,"connection":loaded.home.join("connection.json"),"launch_agent":loaded.home.join("launch-agent.plist"),"label":loaded.config.label})
            );
            Ok(())
        }
        Some("tailcat-plist") if args.len() == 9 => {
            let mut options = std::collections::BTreeMap::new();
            for pair in args[3..].as_chunks::<2>().0.iter() {
                let flag = pair[0].to_str().ok_or(HELP)?;
                if !["--binary", "--key", "--out"].contains(&flag)
                    || options.insert(flag, Path::new(&pair[1])).is_some()
                {
                    return Err(HELP.into());
                }
            }
            let binary = options.get("--binary").ok_or(HELP)?;
            let key = options.get("--key").ok_or(HELP)?;
            let output = options.get("--out").ok_or(HELP)?;
            if !binary.is_absolute() || !key.is_absolute() || !output.is_absolute() {
                return Err(HELP.into());
            }
            launchd::tailcat_plist(&config::load(home)?, binary, key, output)
        }
        Some("add-credential") if args.len() == 3 => {
            let (index, id) = config::add_credential(home)?;
            println!(
                "{}",
                serde_json::json!({"status":"credential_added","home":config::resolve(home)?,"credential_index":index,"credential_id":id,"credential_file":format!("client-{index}.token")})
            );
            Ok(())
        }
        Some("rotate") if args.len() == 3 => {
            let (namespace, mailbox) = config::rotate(home)?;
            println!(
                "{}",
                serde_json::json!({"status":"rotated","home":config::resolve(home)?,"namespace":namespace,"mailbox":mailbox,"connection":config::resolve(home)?.join("connection.json")})
            );
            Ok(())
        }
        Some("renew") if args.len() == 3 => {
            let expires = config::renew(home)?;
            println!(
                "{}",
                serde_json::json!({"status":"renewed","home":config::resolve(home)?,"certificate_expires_at":expires})
            );
            Ok(())
        }
        Some(action @ ("serve" | "status" | "install" | "uninstall"))
            if args.len() == 3 || (action == "status" && args.len() == 4) =>
        {
            let probing = action == "status" && args.len() == 4;
            if probing && args[3] != "--probe" {
                return Err(HELP.into());
            }
            let loaded = if action == "uninstall" {
                config::load_for_stop(home)?
            } else {
                config::load(home)?
            };
            match action {
                "serve" => serve(loaded),
                "status" => {
                    let now = time::OffsetDateTime::now_utc().unix_timestamp();
                    let mut report = serde_json::json!({"status":"configured","home":loaded.home,"label":loaded.config.label,"listen":loaded.config.listen,"tls_name":loaded.config.tls_name,"namespace":loaded.config.namespace,"mailbox":loaded.config.mailbox,"credentials":loaded.config.credential_ids.len(),"certificate_expires_at":loaded.config.certificate_expires_at,"certificate_expired":now>=loaded.config.certificate_expires_at,"certificate_expiring":now>=loaded.config.certificate_expires_at-RENEWAL_WARNING_SECS&&now<loaded.config.certificate_expires_at,"certificate_warning_secs":RENEWAL_WARNING_SECS,"service":launchd::status(&loaded)?,"log":loaded.home.join(launchd::LOG_NAME),"recent_events":events::tail(&loaded.home,8)?});
                    if probing {
                        report["probe"] = probe(&loaded)?;
                    } else {
                        report["health"] =
                            "not probed; loaded service is not TLS or retention evidence".into();
                    }
                    println!("{report}");
                    Ok(())
                }
                "install" => {
                    let result = launchd::install(&loaded);
                    if result.is_ok() {
                        let _ = events::append(&loaded.home, "agent-installed", &[]);
                    }
                    result
                }
                "uninstall" => {
                    let result = launchd::uninstall(&loaded);
                    if result.is_ok() {
                        let _ = events::append(&loaded.home, "agent-uninstalled", &[]);
                    }
                    result
                }
                _ => Err(HELP.into()),
            }
        }
        _ => Err(HELP.into()),
    }
}

fn service(home: &Path, config: &Config) -> Result<Service, String> {
    let namespace =
        RelayNamespace::from_bytes(config::decode_hex(&config.namespace)?).map_err(|_| REFUSED)?;
    let tls = tls::server_config(
        vec![config::read_bound(home, config, "server.der", 65536)?.to_vec()],
        config::read_bound(home, config, "server-key.der", 65536)?.to_vec(),
    )
    .map_err(|_| REFUSED)?;
    let mut credentials = Vec::new();
    for (index, id) in config.credential_ids.iter().enumerate() {
        let raw = config::read_bound(home, config, &format!("client-{}.token", index + 1), 65)?;
        let token = std::str::from_utf8(&raw).map_err(|_| REFUSED)?;
        credentials.push(Credential {
            id: config::decode_hex(id)?,
            namespace,
            tokens: vec![
                RelayToken::from_bytes(config::decode_hex(token.trim_end_matches('\n'))?)
                    .map_err(|_| REFUSED)?,
            ],
            permissions: Permissions {
                put: true,
                page: true,
            },
            storage: Limits {
                max_items: 2048,
                max_bytes: 128 * 1024 * 1024,
            },
            max_inflight: 8,
            requests_per_window: 64,
            bytes_per_window: 32 * 1024 * 1024,
        });
    }
    Service::new(
        FileStore::open(home.join(&config.mailbox), namespace).map_err(|_| REFUSED)?,
        tls,
        credentials,
        ServiceLimits::default(),
    )
    .map_err(|_| REFUSED.into())
}

/// A live probe performs the real pinned-TLS authenticated empty-page check
/// against the configured listener and reports the outcome without secrets.
fn probe(loaded: &Loaded) -> Result<serde_json::Value, String> {
    use std::time::{Duration, Instant};
    let ca = config::read_bound(&loaded.home, &loaded.config, "ca.der", 65536)?;
    let raw = config::read_bound(&loaded.home, &loaded.config, "client-1.token", 65)?;
    let text = std::str::from_utf8(&raw).map_err(|_| REFUSED)?;
    let token = RelayToken::from_bytes(config::decode_hex::<32>(text.trim_end_matches('\n'))?)
        .map_err(|_| REFUSED)?;
    let namespace = RelayNamespace::from_bytes(config::decode_hex(&loaded.config.namespace)?)
        .map_err(|_| REFUSED)?;
    let relay = tls::TlsRelay::new(
        loaded.config.listen,
        &loaded.config.tls_name,
        ca.to_vec(),
        token,
        namespace,
    )
    .map_err(|_| REFUSED)?;
    let listening =
        std::net::TcpStream::connect_timeout(&loaded.config.listen, Duration::from_millis(250))
            .is_ok();
    match relay.page_until(0, 1, Instant::now() + Duration::from_secs(5)) {
        Ok(page) => Ok(
            serde_json::json!({"listening":listening,"probed":true,"head":page.head,"records":page.records.len()}),
        ),
        Err(error) => Ok(
            serde_json::json!({"listening":listening,"probed":false,"error":net_error_name(&error)}),
        ),
    }
}
/// Stable error-kind names for operator tooling; never carries payloads.
fn net_error_name(error: &vhalla_private_native::relay::net::NetError) -> &'static str {
    use vhalla_private_native::relay::net::NetError::*;
    match error {
        Connect => "connect",
        Timeout => "timeout",
        Unavailable => "unavailable",
        Denied => "denied",
        Conflict => "conflict",
        Capacity => "capacity",
        Bounds => "bounds",
        Scope => "scope",
        Malformed => "malformed",
    }
}

fn serve(loaded: Loaded) -> Result<(), String> {
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    if now < loaded.config.created_at - 300 || now >= loaded.config.certificate_expires_at {
        return Err(
            "local TLS certificate is not currently valid; preserve custody and renew explicitly"
                .into(),
        );
    }
    let service = service(&loaded.home, &loaded.config)?;
    // Mailbox custody is held before the bounded bind retry so a restart
    // handoff cannot let a second owner take the store mid-recovery.
    let mut listener = None;
    for attempt in 0..20 {
        match TcpListener::bind(loaded.config.listen) {
            Ok(bound) => {
                listener = Some(bound);
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => {
                events::append(
                    &loaded.home,
                    "bind-retry",
                    &[("attempt", &attempt.to_string())],
                )?;
                std::thread::sleep(std::time::Duration::from_millis(500));
            }
            Err(_) => return Err("local relay bind refused".into()),
        }
    }
    let Some(listener) = listener else {
        return Err("local relay bind refused".into());
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| REFUSED)?;
    runtime.block_on(async {
        use tokio::signal::unix::{signal,SignalKind};
        let mut terminate=signal(SignalKind::terminate()).map_err(|_|REFUSED)?;
        let mut interrupt=signal(SignalKind::interrupt()).map_err(|_|REFUSED)?;
        let stop=Arc::new(AtomicBool::new(false));
        let selected=stop.clone();
        events::append(&loaded.home,"serve-start",&[("listen",&loaded.config.listen.to_string())])?;
        println!("{}",serde_json::json!({"status":"listening","listen":loaded.config.listen,"label":loaded.config.label}));
        let mut worker=tokio::task::spawn_blocking(move||service.serve_until(listener,None,selected));
        let outcome=tokio::select! {
            result=&mut worker => (result.map_err(|_|REFUSED)?.map_err(|_|REFUSED.to_owned()),"worker"),
            _=terminate.recv() => {stop.store(true,Ordering::Release);(worker.await.map_err(|_|REFUSED)?.map_err(|_|REFUSED.to_owned()),"terminate")},
            _=interrupt.recv() => {stop.store(true,Ordering::Release);(worker.await.map_err(|_|REFUSED)?.map_err(|_|REFUSED.to_owned()),"interrupt")},
        };
        let (result,reason)=outcome;
        let _=events::append(&loaded.home,"serve-stop",&[("reason",reason),("ok",if result.is_ok(){"true"}else{"false"})]);
        result
    })
}

fn loopback(listen: SocketAddr) -> bool {
    matches!(listen.ip(), IpAddr::V4(ip) if ip.is_loopback())
        || matches!(listen.ip(),IpAddr::V6(ip) if ip.is_loopback())
}
