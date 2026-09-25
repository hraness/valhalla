//! Explicit local opaque-relay hosting. No account or room custody lives here.
mod config;
pub(crate) mod events;
mod generation;
pub(crate) mod launchd;
// The systemd flow is compiled and unit-tested everywhere; only Linux calls it.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) mod systemd;

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

pub(crate) const HELP: &str = "vhalla private-host init NEW_HOME [--listen IP:PORT] [--advertise IP:PORT[,IP:PORT...]] [--tls-name NAME] [--executable ABSOLUTE_BINARY] [--leaf-days 1-1824]\nvhalla private-host serve|install|uninstall HOME\nvhalla private-host status HOME [--probe]\nvhalla private-host add-credential|rotate|recover HOME\nvhalla private-host generation-inspect PRIVATE_RECEIPT --out PRIVATE_JSON\nvhalla private-host generation-check|generation-prepare HOME --plan PRIVATE_PLAN --receipts PRIVATE_DIRECTORY\nvhalla private-host generation-fence|generation-cutover|generation-recover HOME\nvhalla private-host renew HOME [--leaf-days 1-1824]\nvhalla private-host revoke-credential|replace-credential HOME INDEX\nvhalla private-host tailcat-plist HOME --binary ABSOLUTE_TAILCAT --key ABSOLUTE_SAVED_KEY --out NEW_PRIVATE_PLIST\nOwner-private TLS mailbox with a separate credential per client. It listens on 127.0.0.1:9473 unless --listen names another address of this machine, such as its LAN or public address; --advertise lists up to four addresses clients dial instead, such as a cloud server's public address. install, status and uninstall manage a LaunchAgent on macOS or a systemd user unit on Linux. Maintenance activates at the next drained service restart. No account keys, automatic update, firewall changes, or cloud provisioning.";
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
            let mut advertise = Vec::new();
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
                    "--advertise" => {
                        advertise = pair[1]
                            .to_str()
                            .ok_or(HELP)?
                            .split(',')
                            .map(str::parse)
                            .collect::<Result<Vec<SocketAddr>, _>>()
                            .map_err(|_| HELP)?
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
                        if !leaf_days
                            .checked_mul(86400)
                            .is_some_and(config::valid_leaf_lifetime)
                        {
                            return Err(HELP.into());
                        }
                    }
                    _ => return Err(HELP.into()),
                }
            }
            if !endpoint(listen) {
                return Err("--listen needs one unicast IP address of this machine and a nonzero port; wildcard, multicast, broadcast, link-local and scoped addresses are refused".into());
            }
            if !listener_selection(listen, &advertise) {
                return Err("--advertise needs a LAN or public --listen address and at most four distinct unicast, non-loopback addresses with nonzero ports".into());
            }
            let loaded = config::initialize_with_leaf_lifetime(
                home,
                listen,
                &advertise,
                &name,
                &executable,
                time::Duration::days(leaf_days),
            )?;
            println!(
                "{}",
                serde_json::json!({"status":"initialized","home":loaded.home,"connection":loaded.home.join("connection.json"),"addresses":config::addresses(&loaded.config),"launch_agent":loaded.home.join("launch-agent.plist"),"label":loaded.config.label})
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
                serde_json::json!({"status":"credential_added","home":config::resolve(home)?,"credential_index":index,"credential_id":id,"credential_file":format!("client-{index}.token"),"restart_required":true})
            );
            Ok(())
        }
        Some("recover") if args.len() == 3 => {
            config::recover(home)?;
            println!(
                "{}",
                serde_json::json!({"status":"recovered","home":config::resolve(home)?,"restart_required":true})
            );
            Ok(())
        }
        Some("generation-inspect") if args.len() == 5 && args[3] == "--out" => {
            generation::inspect(Path::new(&args[2]), Path::new(&args[4]))?;
            println!(
                "{}",
                serde_json::json!({"status":"generation_receipt_inspected","output":Path::new(&args[4])})
            );
            Ok(())
        }
        Some(action @ ("generation-check" | "generation-prepare")) if args.len() == 7 && args[3] == "--plan" && args[5] == "--receipts" => {
            generation::check(home, Path::new(&args[4]), Path::new(&args[6]), action == "generation-prepare")?;
            println!("{}", serde_json::json!({"status": if action == "generation-check" {"generation_checked"} else {"generation_prepared"}, "private_evidence":"retained in the exact host home"}));
            Ok(())
        }
        Some(action @ ("generation-fence" | "generation-cutover" | "generation-recover")) if args.len() == 3 => {
            if action == "generation-fence" { generation::fence(home)?; } else { generation::cutover(home)?; }
            println!("{}", serde_json::json!({"status": if action == "generation-fence" {"generation_fenced"} else {"generation_selected"}, "restart_required":true, "private_evidence":"retained in the exact host home"}));
            Ok(())
        }
        Some("rotate") if args.len() == 3 => {
            Err("mailbox rotation is unavailable until a drained generation transition is qualified; clients may retain pending or uncertain work even when this mailbox is empty; the host home is unchanged, preserve its namespace and all client queues".into())
        }
        Some("renew") if args.len() == 3 || (args.len() == 5 && args[3] == "--leaf-days") => {
            let days = if args.len() == 5 {
                Some(args[4].to_str().ok_or(HELP)?.parse().map_err(|_| HELP)?)
            } else {
                None
            };
            let expires = config::renew(home, days)?;
            println!(
                "{}",
                serde_json::json!({"status":"renewed","home":config::resolve(home)?,"certificate_expires_at":expires,"restart_required":true})
            );
            Ok(())
        }
        Some(action @ ("revoke-credential" | "replace-credential")) if args.len() == 4 => {
            let index: usize = args[3].to_str().ok_or(HELP)?.parse().map_err(|_| HELP)?;
            let (id, generation) =
                config::credential_lifecycle(home, index, action == "replace-credential")?;
            println!(
                "{}",
                serde_json::json!({"status":if action == "replace-credential" {"credential_replaced"} else {"credential_revoked"},"home":config::resolve(home)?,"credential_index":index,"credential_id":id,"credential_generation":generation,"restart_required":true,"activation":"next service open after draining the previous service"})
            );
            Ok(())
        }
        Some("serve") if args.len() == 3 => {
            let maintenance = config::maintenance_lock(home)?;
            generation::require_idle(home)?;
            serve(config::load(home)?, maintenance)
        }
        Some(action @ ("status" | "install" | "uninstall"))
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
                "status" => {
                    let now = time::OffsetDateTime::now_utc().unix_timestamp();
                    let mut report = serde_json::json!({"status":"configured","home":loaded.home,"label":loaded.config.label,"listen":loaded.config.listen,"tls_name":loaded.config.tls_name,"namespace":loaded.config.namespace,"mailbox":loaded.config.mailbox,"credentials":loaded.config.credential_ids.len(),"certificate_expires_at":loaded.config.certificate_expires_at,"certificate_expired":now>=loaded.config.certificate_expires_at,"certificate_expiring":now>=loaded.config.certificate_expires_at-RENEWAL_WARNING_SECS&&now<loaded.config.certificate_expires_at,"certificate_warning_secs":RENEWAL_WARNING_SECS,"service":launchd::status(&loaded)?,"log":loaded.home.join(launchd::LOG_NAME),"supervisor_log":loaded.home.join(launchd::SUPERVISOR_LOG_NAME),"recent_events":events::tail(&loaded.home,8)?});
                    report["addresses"] = serde_json::json!(config::addresses(&loaded.config));
                    report["active_credentials"] = (loaded.config.credential_ids.len()
                        - loaded.config.revoked_credential_ids.len())
                    .into();
                    report["revoked_credentials"] =
                        loaded.config.revoked_credential_ids.len().into();
                    report["configuration_version"] = loaded.config.version.into();
                    report["leaf_lifetime_seconds"] = loaded.config.leaf_lifetime_seconds.into();
                    report["activation"] = "configured selection; an already-running service retains its startup selection until drained and restarted".into();
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
    service_ids(home, config, &config.credential_ids)
}

fn service_ids(home: &Path, config: &Config, allowed: &[String]) -> Result<Service, String> {
    let namespace =
        RelayNamespace::from_bytes(config::decode_hex(&config.namespace)?).map_err(|_| REFUSED)?;
    let tls = tls::server_config(
        vec![config::read_bound(home, config, "server.der", 65536)?.to_vec()],
        config::read_bound(home, config, "server-key.der", 65536)?.to_vec(),
    )
    .map_err(|_| REFUSED)?;
    let mut credentials = Vec::new();
    for (index, id) in config.credential_ids.iter().enumerate() {
        if config.revoked_credential_ids.contains(id) || !allowed.contains(id) {
            continue;
        }
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
    if credentials.is_empty() {
        let indexes: Vec<String> = config
            .credential_ids
            .iter()
            .enumerate()
            .filter(|(_, id)| allowed.contains(id))
            .map(|(index, _)| (index + 1).to_string())
            .collect();
        return Err(format!(
            "all transport credentials enrolled in mailbox directory \"{}\" are revoked; run `vhalla private-host replace-credential HOME INDEX` for credential index {} to issue a fresh token that keeps its quota, then retry",
            config.mailbox,
            indexes.join(" or ")
        ));
    }
    Service::new(
        FileStore::open(home.join(&config.mailbox), namespace).map_err(|_| REFUSED)?,
        tls,
        credentials,
        ServiceLimits::default(),
    )
    .map_err(|_| REFUSED.into())
}

/// Read-only material `private invite` embeds for one participant: the
/// published dial addresses plus one enrolled, unrevoked credential's token.
/// The whole home is verified against its sealed manifest before any value is
/// read, so a bundle can only carry current attested host material.
pub(crate) struct InviteMaterial {
    pub namespace: String,
    pub tls_name: String,
    pub addresses: Vec<SocketAddr>,
    pub ca: Vec<u8>,
    pub token: Vec<u8>,
}
pub(crate) fn invite_material(home: &Path, index: usize) -> Result<InviteMaterial, String> {
    let loaded = config::load(home)?;
    if index == 0 || index > loaded.config.credential_ids.len() {
        return Err(format!(
            "credential index {index} is not enrolled; run `vhalla private-host status HOME` for the enrolled indexes"
        ));
    }
    let id = &loaded.config.credential_ids[index - 1];
    if loaded.config.revoked_credential_ids.contains(id) {
        return Err(format!(
            "credential index {index} is revoked; run `vhalla private-host replace-credential HOME {index}` for a fresh token that keeps its quota"
        ));
    }
    let raw = config::read_bound(
        &loaded.home,
        &loaded.config,
        &format!("client-{index}.token"),
        65,
    )?;
    let text = std::str::from_utf8(&raw).map_err(|_| REFUSED)?;
    let token = config::decode_hex::<32>(text.trim_end_matches('\n'))?;
    Ok(InviteMaterial {
        namespace: loaded.config.namespace.clone(),
        tls_name: loaded.config.tls_name.clone(),
        addresses: config::addresses(&loaded.config),
        ca: config::read_bound(&loaded.home, &loaded.config, "ca.der", 65536)?.to_vec(),
        token: token.to_vec(),
    })
}

/// A live probe performs the real pinned-TLS authenticated empty-page check
/// against the configured listener and reports the outcome without secrets.
fn probe(loaded: &Loaded) -> Result<serde_json::Value, String> {
    use std::time::{Duration, Instant};
    let ca = config::read_bound(&loaded.home, &loaded.config, "ca.der", 65536)?;
    let Some(index) = loaded
        .config
        .credential_ids
        .iter()
        .position(|id| !loaded.config.revoked_credential_ids.contains(id))
    else {
        return Ok(serde_json::json!({"probed":false,"error":"no_active_credential"}));
    };
    let raw = config::read_bound(
        &loaded.home,
        &loaded.config,
        &format!("client-{}.token", index + 1),
        65,
    )?;
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

fn serve(loaded: Loaded, maintenance: std::fs::File) -> Result<(), String> {
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    if now < loaded.config.created_at - 300 || now >= loaded.config.certificate_expires_at {
        return Err(
            "local TLS certificate is not currently valid; preserve custody and renew explicitly"
                .into(),
        );
    }
    let mut services = vec![(loaded.config.listen, service(&loaded.home, &loaded.config)?)];
    for retained in &loaded.config.retained_generations {
        let mut selection = loaded.config.clone();
        selection.namespace = retained.namespace.clone();
        selection.mailbox = retained.mailbox.clone();
        selection.listen = retained.listen;
        generation::validate_retained(&loaded.home, retained)?;
        services.push((
            retained.listen,
            service_ids(&loaded.home, &selection, &retained.credential_ids)?,
        ));
    }
    // Launchd output is bounded separately from structured events and cannot
    // refuse startup; a rotation or refusal is itself recorded as an event.
    events::bound_supervisor_output(&loaded.home);
    // At most sixteen generations, each with sixteen connection workers and
    // its existing finite per-window budgets: 256 simultaneous workers total.
    // Acquire every store before binding any listener, then keep them together.
    let mut bound = Vec::new();
    for (address, service) in services {
        let mut listener = None;
        for attempt in 0..20 {
            match TcpListener::bind(address) {
                Ok(value) => {
                    listener = Some(value);
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
                Err(error) if error.kind() == std::io::ErrorKind::AddrNotAvailable => {
                    return Err(format!("relay listener {address} is not an address of this machine; clients dial it, so restore that address (for example with a DHCP reservation) rather than changing the listener"));
                }
                Err(_) => return Err("local relay bind refused".into()),
            }
        }
        bound.push((service, listener.ok_or("local relay bind refused")?));
    }
    drop(maintenance);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| REFUSED)?;
    runtime.block_on(async {
        use tokio::signal::unix::{signal, SignalKind};
        let mut terminate = signal(SignalKind::terminate()).map_err(|_| REFUSED)?;
        let mut interrupt = signal(SignalKind::interrupt()).map_err(|_| REFUSED)?;
        let stop = Arc::new(AtomicBool::new(false));
        events::append(&loaded.home,"serve-start",&[("listen",&loaded.config.listen.to_string())])?;
        let mut workers = tokio::task::JoinSet::new();
        for (service, listener) in bound {
            let selected = stop.clone();
            workers.spawn_blocking(move || service.serve_until(listener, None, selected));
        }
        println!("{}",serde_json::json!({"status":"listening","listen":loaded.config.listen,"label":loaded.config.label,"generations":workers.len()}));
        let (mut result, reason) = tokio::select! {
            first = workers.join_next() => (match first { Some(Ok(Ok(()))) => Ok(()), _ => Err(REFUSED.to_owned()) }, "worker"),
            _ = terminate.recv() => (Ok(()), "terminate"),
            _ = interrupt.recv() => (Ok(()), "interrupt"),
        };
        stop.store(true, Ordering::Release);
        while let Some(joined) = workers.join_next().await {
            if !matches!(joined, Ok(Ok(()))) { result = Err(REFUSED.to_owned()); }
        }
        let _ = events::append(&loaded.home,"serve-stop",&[("reason",reason),("ok",if result.is_ok(){"true"}else{"false"})]);
        result
    })
}

fn loopback(listen: SocketAddr) -> bool {
    matches!(listen.ip(), IpAddr::V4(ip) if ip.is_loopback())
        || matches!(listen.ip(),IpAddr::V6(ip) if ip.is_loopback())
}

/// Most addresses a host advertises in place of its listener.
const MAX_ADVERTISED: usize = 4;

/// One dialable unicast IP address with a nonzero port. Wildcards, multicast,
/// broadcast, IPv4-mapped IPv6, zoned IPv6 and link-local addresses are
/// refused, so the bound socket, the connection document and each client's
/// pinned endpoint all name one address that means the same on every link.
fn endpoint(address: SocketAddr) -> bool {
    address.port() != 0
        && match address {
            SocketAddr::V4(v4) => {
                let ip = v4.ip();
                !ip.is_unspecified()
                    && !ip.is_multicast()
                    && !ip.is_broadcast()
                    && !ip.is_link_local()
            }
            SocketAddr::V6(v6) => {
                let ip = v6.ip();
                v6.scope_id() == 0
                    && !ip.is_unspecified()
                    && !ip.is_multicast()
                    && !ip.is_unicast_link_local()
                    && ip.to_ipv4_mapped().is_none()
            }
        }
}

/// A listener and the addresses clients dial instead of it. Advertising is
/// only for a network listener whose reachable address differs, such as a
/// cloud server whose interface holds a private address behind 1:1 NAT.
fn listener_selection(listen: SocketAddr, advertise: &[SocketAddr]) -> bool {
    endpoint(listen)
        && advertise.len() <= MAX_ADVERTISED
        && (advertise.is_empty() || !loopback(listen))
        && advertise.iter().all(|a| endpoint(*a) && !loopback(*a))
        && advertise
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            == advertise.len()
}

#[cfg(test)]
mod listener_tests {
    use super::*;
    fn at(text: &str) -> SocketAddr {
        text.parse().unwrap()
    }

    #[test]
    fn a_listener_names_one_dialable_unicast_address() {
        for good in [
            "127.0.0.1:9473",
            "[::1]:9473",
            "192.168.1.20:9473",
            "10.0.0.5:9473",
            "203.0.113.7:443",
            "[2001:db8::7]:9473",
            "[fd00::20]:9473",
        ] {
            assert!(endpoint(at(good)), "{good}");
        }
        for bad in [
            "192.168.1.20:0",
            "0.0.0.0:9473",
            "[::]:9473",
            "224.0.0.1:9473",
            "255.255.255.255:9473",
            "169.254.10.20:9473",
            "[ff02::1]:9473",
            "[fe80::1]:9473",
            "[fe80::1%2]:9473",
            "[2001:db8::7%2]:9473",
            "[::ffff:192.168.1.20]:9473",
        ] {
            assert!(!endpoint(at(bad)), "{bad}");
        }
    }

    #[test]
    fn advertised_addresses_are_distinct_remote_and_only_for_network_listeners() {
        let lan = at("10.0.0.5:9473");
        let public = at("203.0.113.7:9473");
        assert!(listener_selection(at("127.0.0.1:9473"), &[]));
        assert!(listener_selection(lan, &[]));
        assert!(listener_selection(lan, &[public]));
        assert!(listener_selection(
            lan,
            &[
                public,
                at("[2001:db8::7]:9473"),
                at("198.51.100.2:9473"),
                at("198.51.100.3:1")
            ]
        ));
        assert!(!listener_selection(at("127.0.0.1:9473"), &[public]));
        assert!(!listener_selection(lan, &[at("127.0.0.1:9473")]));
        assert!(!listener_selection(lan, &[at("0.0.0.0:9473")]));
        assert!(!listener_selection(lan, &[public, public]));
        assert!(!listener_selection(
            lan,
            &[
                public,
                at("198.51.100.1:9473"),
                at("198.51.100.2:9473"),
                at("198.51.100.3:9473"),
                at("198.51.100.4:9473")
            ]
        ));
        assert!(!listener_selection(at("0.0.0.0:9473"), &[public]));
    }
}
