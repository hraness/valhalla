//! Loopback UI and browser relay gateway. Never opens a mailbox or identity.
mod launchd;
use crate::private_host::events;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    ffi::OsString,
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
use vhalla_private_native::relay::{
    http::{Assets, BrowserCapability, Gateway, GatewayLimits, MAX_ASSET_BYTES},
    net::RelayToken,
    tls::TlsRelay,
    RelayNamespace, MAX_RELAY_ITEMS,
};
use zeroize::Zeroizing;
#[cfg(test)]
mod tests;

const REFUSED: &str =
    "private gateway refused; preserve the exact configuration, assets and event log";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Upstream {
    addr: SocketAddr,
    tls_name: String,
    tls_ca_file: PathBuf,
    token_file: PathBuf,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    format: u32,
    listen: SocketAddr,
    namespace: String,
    browser_token_file: PathBuf,
    upstream: Upstream,
    assets_dir: PathBuf,
    initial_cursor: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    format: u32,
    purpose: String,
    assets: BTreeMap<String, Entry>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    bytes: usize,
    sha256: String,
}
fn hex(raw: &str) -> Result<[u8; 32], String> {
    if raw.len() != 64
        || !raw
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("gateway requires canonical lowercase hex".into());
    }
    let mut out = [0; 32];
    for (i, pair) in raw.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        out[i] = u8::from_str_radix(std::str::from_utf8(pair).map_err(|_| "gateway hex")?, 16)
            .map_err(|_| "gateway hex")?;
    }
    Ok(out)
}
fn private(path: &Path, max: usize) -> Result<Zeroizing<Vec<u8>>, String> {
    if !path.is_absolute() {
        return Err("gateway configuration needs absolute paths".into());
    }
    let (_dir, uid) = vhalla_custody::open_private_directory(
        path.parent().ok_or("gateway private parent required")?,
    )
    .map_err(|_| "gateway configuration parent must be owner-private 0700")?;
    vhalla_custody::read_private_file(path, uid, max)
        .map(Zeroizing::new)
        .map_err(|_| "gateway configuration must be bounded owner-private 0600 files".into())
}
fn token(path: &Path) -> Result<[u8; 32], String> {
    let raw = private(path, 65)?;
    let text = std::str::from_utf8(&raw).map_err(|_| "gateway token encoding")?;
    hex(text.strip_suffix('\n').unwrap_or(text))
}
fn asset(path: &Path, max: usize) -> Result<Vec<u8>, String> {
    use rustix::fs::{open, Mode, OFlags};
    let fd = open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| "gateway artifact unavailable")?;
    let mut file = std::fs::File::from(fd);
    let metadata = file.metadata().map_err(|_| "gateway artifact metadata")?;
    if !metadata.is_file() || metadata.len() > max as u64 {
        return Err("gateway artifact exceeds bounds or is not regular".into());
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(max as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "gateway artifact read")?;
    if bytes.len() > max {
        return Err("gateway artifact grew beyond bounds".into());
    }
    Ok(bytes)
}
fn assets(root: &Path) -> Result<Assets, String> {
    if !root.is_absolute() || !root.is_dir() {
        return Err("gateway requires an absolute packaged production artifact directory".into());
    }
    let manifest: Manifest = serde_json::from_slice(&asset(&root.join("artifact.json"), 65536)?)
        .map_err(|_| "gateway artifact manifest malformed")?;
    if manifest.format != 1 || manifest.purpose != "production" || manifest.assets.len() > 64 {
        return Err(
            "gateway requires a bounded production artifact, never qualification hooks".into(),
        );
    }
    let mut values = BTreeMap::new();
    let mut total = 0usize;
    for (name, entry) in manifest.assets {
        if name.is_empty()
            || name.len() > 128
            || name.starts_with('.')
            || name.contains("..")
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
            || entry.bytes == 0
            || entry.bytes > 32 * 1024 * 1024
        {
            return Err("gateway artifact path or size refused".into());
        }
        total = total
            .checked_add(entry.bytes)
            .ok_or("gateway artifact size overflow")?;
        if total > MAX_ASSET_BYTES {
            return Err("gateway artifact aggregate bound".into());
        }
        let bytes = asset(&root.join(&name), entry.bytes)?;
        if bytes.len() != entry.bytes
            || <[u8; 32]>::from(Sha256::digest(&bytes)) != hex(&entry.sha256)?
        {
            return Err("gateway artifact hash mismatch".into());
        }
        if (name.ends_with(".js") || name.ends_with(".wasm"))
            && [
                b"/__qualification/".as_slice(),
                b"qualify_private_session",
                b"qualify_private_cancel",
            ]
            .iter()
            .any(|marker| bytes.windows(marker.len()).any(|part| part == *marker))
        {
            return Err("gateway refuses qualification code".into());
        }
        values.insert(name, bytes);
    }
    Assets::new(values).map_err(|_| "gateway artifact allowlist refused".into())
}
/// Load exact immutable gateway configuration; the browser receives neither the
/// upstream token nor CA/key paths. This performs no network or mailbox effects.
pub(crate) fn load(path: &Path) -> Result<(Gateway, SocketAddr), String> {
    let config: Config = serde_json::from_slice(&private(path, 65536)?)
        .map_err(|_| "gateway configuration malformed")?;
    if config.format != 1
        || !config.listen.ip().is_loopback()
        || config.listen.port() == 0
        || config
            .initial_cursor
            .parse::<u64>()
            .ok()
            .is_none_or(|n| n.to_string() != config.initial_cursor || n > MAX_RELAY_ITEMS as u64)
    {
        return Err(
            "gateway needs format 1, fixed loopback port and canonical initial_cursor within mailbox capacity".into(),
        );
    }
    let namespace = RelayNamespace::from_bytes(hex(&config.namespace)?)
        .map_err(|_| "gateway namespace refused")?;
    let browser_token = Zeroizing::new(token(&config.browser_token_file)?);
    let upstream_token = Zeroizing::new(token(&config.upstream.token_file)?);
    if *browser_token == *upstream_token {
        return Err("browser capability must differ from upstream TLS credential".into());
    }
    let client = TlsRelay::new(
        config.upstream.addr,
        &config.upstream.tls_name,
        private(&config.upstream.tls_ca_file, 65536)?.to_vec(),
        RelayToken::from_bytes(*upstream_token)
            .map_err(|_| "gateway upstream credential refused")?,
        namespace,
    )
    .map_err(|_| "gateway TLS profile refused")?;
    let gateway = Gateway::new(
        config.listen,
        namespace,
        BrowserCapability::from_bytes(*browser_token)
            .map_err(|_| "gateway browser capability refused")?,
        client,
        assets(&config.assets_dir)?,
        GatewayLimits::default(),
    )
    .map_err(|_| "gateway policy refused")?;
    Ok((gateway, config.listen))
}
/// Canonical absolute path used for labels, argv and the sibling event log.
fn resolve(path: &Path) -> Result<PathBuf, String> {
    let absolute = vhalla_custody::absolute(path).map_err(|_| REFUSED)?;
    let parent = absolute
        .parent()
        .ok_or(REFUSED)?
        .canonicalize()
        .map_err(|_| REFUSED)?;
    let name = absolute.file_name().ok_or(REFUSED)?;
    if name == "." || name == ".." {
        return Err(REFUSED.into());
    }
    Ok(parent.join(name))
}
/// Live check: the loopback listener accepts TCP and answers an exact-origin
/// GET for the packaged index — never a substitute for upstream TLS evidence.
fn probe(listen: SocketAddr) -> Result<serde_json::Value, String> {
    let host = listen.to_string();
    let listening = TcpStream::connect_timeout(&listen, Duration::from_millis(250)).is_ok();
    let probed = (|| -> Result<bool, String> {
        let mut stream =
            TcpStream::connect_timeout(&listen, Duration::from_secs(2)).map_err(|_| REFUSED)?;
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .and_then(|()| stream.set_write_timeout(Some(Duration::from_secs(3))))
            .map_err(|_| REFUSED)?;
        stream
            .write_all(
                format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes(),
            )
            .map_err(|_| REFUSED)?;
        let mut head = [0u8; 32];
        let mut filled = 0;
        while filled < 13 {
            let n = stream
                .read(&mut head[filled..])
                .map_err(|_| "gateway probe read refused")?;
            if n == 0 {
                return Ok(false);
            }
            filled += n;
        }
        Ok(head.starts_with(b"HTTP/1.1 200"))
    })();
    match probed {
        Ok(ok) => Ok(serde_json::json!({"listening":listening,"probed":ok})),
        Err(_) => Ok(serde_json::json!({"listening":listening,"probed":false})),
    }
}
/// Bounded bind retry mirrors the host: a restart handoff or brief port hold
/// must not drop the supervisor into a crash loop. Non-address errors refuse.
fn bind(address: SocketAddr, log_dir: &Path) -> Result<TcpListener, String> {
    for attempt in 0..20 {
        match TcpListener::bind(address) {
            Ok(listener) => return Ok(listener),
            Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => {
                events::append(log_dir, "bind-retry", &[("attempt", &attempt.to_string())])?;
                std::thread::sleep(Duration::from_millis(500));
            }
            Err(_) => return Err("gateway loopback listener bind failed".into()),
        }
    }
    Err("gateway loopback listener bind failed".into())
}
pub(crate) fn help() -> &'static str {
    "vhalla private-gateway serve|status|install|uninstall <absolute-private-config.json> [--probe for status]"
}
pub(crate) fn execute(args: &[OsString]) -> Result<(), String> {
    if args.is_empty() {
        return Err(help().into());
    }
    match args[0].to_str() {
        Some("status") if args.len() == 2 || args.len() == 3 => {
            if args.len() == 3 && args[2] != "--probe" {
                return Err(help().into());
            }
            let config = resolve(Path::new(&args[1]))?;
            let (gateway, listen) = load(&config)?;
            let log_dir = config.parent().ok_or(REFUSED)?;
            let mut report = serde_json::json!({"status":"configured","config":config,"label":launchd::label(&config)?,"listen":listen,"origin":gateway.origin(),"service":launchd::status(&config)?,"log":log_dir.join(crate::private_host::launchd::LOG_NAME),"recent_events":events::tail(log_dir,8)?});
            if args.len() == 3 {
                report["probe"] = probe(listen)?;
            } else {
                report["health"] =
                    "not probed; live listener and upstream TLS are separate evidence".into();
            }
            println!("{report}");
            Ok(())
        }
        Some("install") if args.len() == 2 => {
            let config = resolve(Path::new(&args[1]))?;
            // Never install an agent for configuration that cannot serve.
            drop(load(&config)?);
            let result = launchd::install(&config);
            if result.is_ok() {
                let _ = events::append(config.parent().ok_or(REFUSED)?, "agent-installed", &[]);
            }
            result
        }
        Some("uninstall") if args.len() == 2 => {
            let config = resolve(Path::new(&args[1]))?;
            let result = launchd::uninstall(&config);
            if result.is_ok() {
                let _ = events::append(config.parent().ok_or(REFUSED)?, "agent-uninstalled", &[]);
            }
            result
        }
        Some("serve") if args.len() == 2 => serve(Path::new(&args[1])),
        _ => Err(help().into()),
    }
}
fn serve(path: &Path) -> Result<(), String> {
    let config = resolve(path)?;
    let (gateway, address) = load(&config)?;
    let log_dir = config.parent().ok_or(REFUSED)?.to_path_buf();
    let listener = bind(address, &log_dir)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| REFUSED)?;
    runtime.block_on(async {
        use tokio::signal::unix::{signal, SignalKind};
        let mut terminate = signal(SignalKind::terminate()).map_err(|_| REFUSED)?;
        let mut interrupt = signal(SignalKind::interrupt()).map_err(|_| REFUSED)?;
        let stop = Arc::new(AtomicBool::new(false));
        let selected = stop.clone();
        events::append(&log_dir, "serve-start", &[("listen", &address.to_string())])?;
        println!("private-gateway {}", gateway.origin());
        let mut worker =
            tokio::task::spawn_blocking(move || gateway.serve_until(listener, selected));
        let (result, reason) = tokio::select! {
            result = &mut worker => (result.map_err(|_|REFUSED)?,"worker"),
            _ = terminate.recv() => {stop.store(true,Ordering::Release);(worker.await.map_err(|_|REFUSED)?,"terminate")},
            _ = interrupt.recv() => {stop.store(true,Ordering::Release);(worker.await.map_err(|_|REFUSED)?,"interrupt")},
        };
        let _ = events::append(&log_dir, "serve-stop", &[("reason", reason)]);
        result.map_err(|_| "gateway service stopped; preserve configuration and stores".into())
    })
}
