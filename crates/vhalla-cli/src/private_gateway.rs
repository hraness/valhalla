//! Loopback UI and browser relay gateway. Never opens a mailbox or identity.
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    ffi::OsString,
    io::Read,
    net::{SocketAddr, TcpListener},
    path::{Path, PathBuf},
    sync::{atomic::AtomicBool, Arc},
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
pub(crate) fn help() -> &'static str {
    "vhalla private-gateway serve <absolute-private-config.json>"
}
pub(crate) fn execute(args: &[OsString]) -> Result<(), String> {
    if args.len() != 2 || args[0] != "serve" {
        return Err(help().into());
    }
    let (gateway, address) = load(Path::new(&args[1]))?;
    let listener =
        TcpListener::bind(address).map_err(|_| "gateway loopback listener bind failed")?;
    println!("private-gateway {}", gateway.origin());
    gateway
        .serve_until(listener, Arc::new(AtomicBool::new(false)))
        .map_err(|_| "gateway service stopped; preserve configuration and stores".into())
}
