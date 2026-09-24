//! Same-origin loopback HTTP or explicit HTTPS gateway to one pinned TLS relay.
//! No mailbox is opened here. Admission precedes upstream network effects.
use super::{codec::*, net::NetError, tls::TlsRelay, RelayItem, RelayNamespace};
use rustls::{ServerConfig, ServerConnection, StreamOwned};
use std::{
    collections::BTreeMap,
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    panic::{catch_unwind, AssertUnwindSafe},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
pub use vhalla_private_relay::http_origin::HttpsOrigin;
#[cfg(test)]
mod tests;
type Result<T> = std::result::Result<T, NetError>;
const HEADER_MAX: usize = 8192;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(3);
/// Maximum explicitly selected lifetime for a newly loaded HTTPS client.
pub const MAX_BROWSER_CLIENT_LIFETIME: Duration = Duration::from_secs(7 * 24 * 60 * 60);
/// Fixed HTTP endpoint; callers cannot choose an upstream route.
pub const ENDPOINT: &str = "/private-relay/v1";
/// Public UI artifact memory cap, separate from relay ciphertext bounds.
pub const MAX_ASSET_BYTES: usize = 64 * 1024 * 1024;
const CSP: &str = "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; worker-src 'self'; connect-src 'self' https:; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'";

/// Independent browser admission secret. Never reuse the upstream relay token.
#[derive(Clone)]
pub struct BrowserCapability([u8; 32]);
impl std::fmt::Debug for BrowserCapability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BrowserCapability([REDACTED])")
    }
}
impl BrowserCapability {
    /// Admit a nonzero, independently generated capability.
    pub fn from_bytes(value: [u8; 32]) -> Result<Self> {
        if value == [0; 32] {
            return Err(NetError::Bounds);
        }
        Ok(Self(value))
    }
    fn matches(&self, value: &str) -> bool {
        let Some(value) = value.strip_prefix("Bearer ") else {
            return false;
        };
        let Some(bytes) = hex32(value) else {
            return false;
        };
        self.0
            .iter()
            .zip(bytes)
            .fold(0u8, |diff, (a, b)| diff | (a ^ b))
            == 0
    }
}
/// One independently revocable hosted browser credential. These budgets limit
/// admitted browser bodies and concurrent requests; they never reset or replace
/// durable relay quota. A bounded upstream reply can be read before refusal.
pub struct BrowserClient {
    /// Stable nonzero administration identifier, not a room or account identity.
    pub id: [u8; 16],
    /// Independent browser secret, distinct from every other and upstream token.
    pub capability: BrowserCapability,
    /// Explicit UNIX-seconds expiry; expired entries remain denied.
    pub expires_unix_secs: u64,
    /// Administratively disabled until an explicit drained configuration change.
    pub revoked: bool,
    /// Maximum concurrent authenticated requests, from one through eight.
    pub max_inflight: usize,
    /// Requests per gateway window, from one through 4,096.
    pub requests_per_window: u32,
    /// Admitted browser request and reply frame bytes per window, at most 64 MiB.
    /// An upstream reply read before this check may exceed the remaining budget.
    pub bytes_per_window: usize,
}

/// Explicit HTTPS termination settings. No forwarded header can enable TLS.
pub struct HttpsSettings {
    /// Exact public HTTPS origin selected before browser custody initialization.
    pub origin: HttpsOrigin,
    /// DER certificate chain, leaf first, under ordinary browser trust.
    pub certificate_chain: Vec<Vec<u8>>,
    /// PKCS#8 DER key matching the leaf certificate.
    pub private_key: Vec<u8>,
    /// One through 64 distinct browser credentials.
    pub clients: Vec<BrowserClient>,
}

struct ClientState {
    selected: BrowserClient,
    expires: Option<Instant>,
    disabled: bool,
    budget: Budget,
    inflight: usize,
}
impl ClientState {
    fn live(&mut self, now: Instant, wall: u64) -> bool {
        self.disabled |= self.selected.revoked
            || wall >= self.selected.expires_unix_secs
            || self.expires.is_none_or(|expires| now >= expires);
        !self.disabled
    }
}
struct Hosted {
    tls: Arc<ServerConfig>,
    name: String,
    clients: Mutex<Vec<ClientState>>,
}

fn unix_now() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| NetError::Unavailable)
}

struct ClientLease<'a> {
    state: &'a State,
    index: usize,
}
impl ClientLease<'_> {
    fn charge(&self, bytes: usize) -> Result<bool> {
        let hosted = self.state.hosted.as_ref().ok_or(NetError::Unavailable)?;
        let mut clients = hosted.clients.lock().map_err(|_| NetError::Unavailable)?;
        let client = &mut clients[self.index];
        let now = Instant::now();
        if now.duration_since(client.budget.start) >= self.state.limits.window {
            client.budget = Budget {
                start: now,
                requests: 0,
                bytes: 0,
            };
        }
        if bytes
            > client
                .selected
                .bytes_per_window
                .saturating_sub(client.budget.bytes)
        {
            return Ok(false);
        }
        client.budget.bytes += bytes;
        Ok(true)
    }
    fn live(&self) -> Result<bool> {
        let hosted = self.state.hosted.as_ref().ok_or(NetError::Unavailable)?;
        let mut clients = hosted.clients.lock().map_err(|_| NetError::Unavailable)?;
        Ok(clients[self.index].live(Instant::now(), unix_now()?))
    }
}
impl Drop for ClientLease<'_> {
    fn drop(&mut self) {
        let Some(hosted) = &self.state.hosted else {
            return;
        };
        match hosted.clients.lock() {
            Ok(mut clients) => {
                let client = &mut clients[self.index];
                if let Some(next) = client.inflight.checked_sub(1) {
                    client.inflight = next;
                } else {
                    self.state.unhealthy.store(true, Ordering::Release);
                }
            }
            Err(_) => self.state.unhealthy.store(true, Ordering::Release),
        }
    }
}

enum Authorized<'a> {
    Allowed(Option<ClientLease<'a>>),
    Denied,
    Busy,
}
fn authorize<'a>(state: &'a State, header: Option<&str>) -> Result<Authorized<'a>> {
    let Some(header) = header else {
        return Ok(Authorized::Denied);
    };
    let Some(hosted) = &state.hosted else {
        return Ok(if state.capability.matches(header) {
            Authorized::Allowed(None)
        } else {
            Authorized::Denied
        });
    };
    let mut clients = hosted.clients.lock().map_err(|_| NetError::Unavailable)?;
    let Some(index) = clients
        .iter()
        .position(|client| client.selected.capability.matches(header))
    else {
        return Ok(Authorized::Denied);
    };
    let client = &mut clients[index];
    let now = Instant::now();
    if !client.live(now, unix_now()?) {
        return Ok(Authorized::Denied);
    }
    if now.duration_since(client.budget.start) >= state.limits.window {
        client.budget = Budget {
            start: now,
            requests: 0,
            bytes: 0,
        };
    }
    if client.inflight >= client.selected.max_inflight
        || client.budget.requests >= client.selected.requests_per_window
    {
        return Ok(Authorized::Busy);
    }
    client.budget.requests += 1;
    client.inflight += 1;
    Ok(Authorized::Allowed(Some(ClientLease { state, index })))
}
fn hex32(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    let mut out = [0; 32];
    for (i, pair) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        out[i] = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(out)
}
/// Finite concurrent work, admission rate, and complete HTTP request deadline.
#[derive(Clone, Copy)]
pub struct GatewayLimits {
    /// At most this many accepted connections run concurrently (1..16).
    pub max_connections: usize,
    /// Includes request parsing, TLS upstream and response write (at most 25s).
    pub timeout: Duration,
    /// Local monotonic accounting window, at most one minute.
    pub window: Duration,
    /// Total accepted connections per window, including unauthenticated peers.
    pub requests: u32,
    /// Total request and response body bytes admitted per window.
    pub bytes: usize,
}
impl Default for GatewayLimits {
    fn default() -> Self {
        Self {
            max_connections: 8,
            timeout: Duration::from_secs(10),
            window: Duration::from_secs(10),
            requests: 128,
            bytes: 64 * 1024 * 1024,
        }
    }
}
impl GatewayLimits {
    fn check(self) -> Result<()> {
        if !(1..=16).contains(&self.max_connections)
            || self.timeout.is_zero()
            || self.timeout > Duration::from_secs(25)
            || self.window.is_zero()
            || self.window > Duration::from_secs(60)
            || self.requests == 0
            || self.requests > 4096
            || self.bytes == 0
            || self.bytes > 64 * 1024 * 1024
        {
            return Err(NetError::Bounds);
        }
        Ok(())
    }
}
/// Immutable preverified production assets. Serving never reads arbitrary paths.
pub struct Assets(BTreeMap<String, Vec<u8>>);
impl Assets {
    /// Accept only a bounded flat manifest allowlist. The CLI verifies hashes and
    /// production purpose before constructing this value; no credentials belong here.
    pub fn new(values: BTreeMap<String, Vec<u8>>) -> Result<Self> {
        if values.is_empty() || values.len() > 64 || !values.contains_key("index.html") {
            return Err(NetError::Bounds);
        }
        let mut total = 0usize;
        for (name, bytes) in &values {
            if name.is_empty()
                || name.len() > 128
                || name.starts_with('.')
                || name.contains("..")
                || !name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
                || bytes.is_empty()
                || bytes.len() > 32 * 1024 * 1024
            {
                return Err(NetError::Bounds);
            }
            total = total.checked_add(bytes.len()).ok_or(NetError::Bounds)?;
        }
        if total > MAX_ASSET_BYTES {
            return Err(NetError::Bounds);
        }
        Ok(Self(values))
    }
}
trait Upstream: Send + Sync {
    fn exchange(&self, op: u8, body: &[u8], deadline: Instant) -> Result<Vec<u8>>;
}
impl Upstream for TlsRelay {
    fn exchange(&self, op: u8, body: &[u8], deadline: Instant) -> Result<Vec<u8>> {
        match op {
            OP_PUT => self
                .submit_until(
                    &RelayItem::decode(body).map_err(|_| NetError::Malformed)?,
                    deadline,
                )
                .map(encode_receipt),
            OP_PAGE => {
                let after = u64::from_be_bytes(body[..8].try_into().expect("validated"));
                let limit = u16::from_be_bytes(body[8..].try_into().expect("validated")) as usize;
                encode_page(&self.page_until(after, limit, deadline)?)
            }
            _ => Err(NetError::Bounds),
        }
    }
}
struct Budget {
    start: Instant,
    requests: u32,
    bytes: usize,
}
struct State {
    address: SocketAddr,
    host: String,
    origin: String,
    namespace: RelayNamespace,
    capability: BrowserCapability,
    hosted: Option<Hosted>,
    limits: GatewayLimits,
    upstream: Arc<dyn Upstream>,
    assets: Assets,
    budget: Mutex<Budget>,
    unhealthy: AtomicBool,
}
/// Bounded host-owned HTTP gateway, independent from room/identity custody.
pub struct Gateway(Arc<State>);
impl Gateway {
    /// Bind configuration to one loopback address and one TLS namespace. The
    /// caller must keep browser and upstream capabilities distinct. HTTP's
    /// default port 80 is refused because browser origins omit that port.
    pub fn new(
        address: SocketAddr,
        namespace: RelayNamespace,
        capability: BrowserCapability,
        upstream: TlsRelay,
        assets: Assets,
        limits: GatewayLimits,
    ) -> Result<Self> {
        if upstream.token_matches(&capability.0) {
            return Err(NetError::Denied);
        }
        if upstream.namespace() != namespace {
            return Err(NetError::Scope);
        }
        Self::configured(
            address,
            namespace,
            capability,
            Arc::new(upstream),
            assets,
            limits,
        )
    }
    /// Construct direct TLS 1.3 termination for one canonical DNS origin.
    /// It never enables plaintext remote HTTP, proxy headers or ambient upstream trust.
    pub fn new_https(
        address: SocketAddr,
        namespace: RelayNamespace,
        settings: HttpsSettings,
        upstream: TlsRelay,
        assets: Assets,
        limits: GatewayLimits,
    ) -> Result<Self> {
        if upstream.namespace() != namespace {
            return Err(NetError::Scope);
        }
        if settings
            .clients
            .iter()
            .any(|client| upstream.token_matches(&client.capability.0))
        {
            return Err(NetError::Denied);
        }
        Self::configured_https(
            address,
            namespace,
            settings,
            Arc::new(upstream),
            assets,
            limits,
        )
    }
    fn configured_https(
        address: SocketAddr,
        namespace: RelayNamespace,
        settings: HttpsSettings,
        upstream: Arc<dyn Upstream>,
        assets: Assets,
        limits: GatewayLimits,
    ) -> Result<Self> {
        limits.check()?;
        if address.port() == 0
            || address.port() != settings.origin.port()
            || settings.clients.is_empty()
            || settings.clients.len() > 64
        {
            return Err(NetError::Bounds);
        }
        let wall = unix_now()?;
        let now = Instant::now();
        let mut clients = Vec::<ClientState>::new();
        for selected in settings.clients {
            if selected.id == [0; 16]
                || !(1..=8).contains(&selected.max_inflight)
                || !(1..=4096).contains(&selected.requests_per_window)
                || !(1..=64 * 1024 * 1024).contains(&selected.bytes_per_window)
                || (!selected.revoked
                    && selected.expires_unix_secs.saturating_sub(wall)
                        > MAX_BROWSER_CLIENT_LIFETIME.as_secs())
                || clients.iter().any(|prior| {
                    prior.selected.id == selected.id
                        || prior.selected.capability.0 == selected.capability.0
                })
            {
                return Err(NetError::Bounds);
            }
            let remaining = selected.expires_unix_secs.saturating_sub(wall);
            let disabled = selected.revoked || remaining == 0;
            clients.push(ClientState {
                selected,
                expires: (!disabled).then(|| now + Duration::from_secs(remaining)),
                disabled,
                budget: Budget {
                    start: now,
                    requests: 0,
                    bytes: 0,
                },
                inflight: 0,
            });
        }
        let mut tls = super::tls::server_config(settings.certificate_chain, settings.private_key)?;
        Arc::get_mut(&mut tls)
            .ok_or(NetError::Unavailable)?
            .alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Self(Arc::new(State {
            address,
            host: settings.origin.authority().to_owned(),
            origin: settings.origin.as_str().to_owned(),
            // Unused for HTTPS, which always uses its explicit client table.
            capability: BrowserCapability([0; 32]),
            hosted: Some(Hosted {
                tls,
                name: settings.origin.host().to_owned(),
                clients: Mutex::new(clients),
            }),
            namespace,
            upstream,
            assets,
            limits,
            budget: Mutex::new(Budget {
                start: now,
                requests: 0,
                bytes: 0,
            }),
            unhealthy: AtomicBool::new(false),
        })))
    }
    fn configured(
        address: SocketAddr,
        namespace: RelayNamespace,
        capability: BrowserCapability,
        upstream: Arc<dyn Upstream>,
        assets: Assets,
        limits: GatewayLimits,
    ) -> Result<Self> {
        limits.check()?;
        if !address.ip().is_loopback() || matches!(address.port(), 0 | 80) {
            return Err(NetError::Bounds);
        }
        let host = address.to_string();
        Ok(Self(Arc::new(State {
            address,
            origin: format!("http://{host}"),
            host,
            namespace,
            capability,
            hosted: None,
            upstream,
            assets,
            limits,
            budget: Mutex::new(Budget {
                start: Instant::now(),
                requests: 0,
                bytes: 0,
            }),
            unhealthy: AtomicBool::new(false),
        })))
    }
    /// Exact selected browser origin; construction determines HTTP or HTTPS.
    pub fn origin(&self) -> &str {
        &self.0.origin
    }
    /// Stop admission on the host's flag, drain finite deadline-bound workers,
    /// and close the listener. There are no detached gateway threads.
    pub fn serve_until(self, listener: TcpListener, stop: Arc<AtomicBool>) -> Result<()> {
        self.serve_with(listener, stop, handle_tracked)
    }
    fn serve_with(
        self,
        listener: TcpListener,
        stop: Arc<AtomicBool>,
        handler: impl Fn(&State, TcpStream, &mut bool) -> Result<()> + Send + Sync + 'static,
    ) -> Result<()> {
        if listener.local_addr().map_err(|_| NetError::Unavailable)? != self.0.address {
            return Err(NetError::Scope);
        }
        listener
            .set_nonblocking(true)
            .map_err(|_| NetError::Unavailable)?;
        let mut workers: Vec<thread::JoinHandle<bool>> = Vec::new();
        let handler = Arc::new(handler);
        let mut failed = false;
        while !stop.load(Ordering::Acquire) {
            let mut index = 0;
            while index < workers.len() {
                if workers[index].is_finished() {
                    failed |= workers.swap_remove(index).join().unwrap_or(true);
                } else {
                    index += 1;
                }
            }
            if failed || self.0.unhealthy.load(Ordering::Acquire) {
                failed = true;
                break;
            }
            match listener.accept() {
                Ok((stream, peer)) => {
                    let admitted = match admit(&self.0, 0, true) {
                        Ok(value) => value,
                        Err(_) => {
                            failed = true;
                            break;
                        }
                    };
                    // Admission refusals answer with an explicit status instead
                    // of silently dropping the socket: 403 for a non-loopback
                    // peer, 503 while every worker slot is occupied, and 429
                    // once the accepted-connection window budget is spent.
                    if self.0.hosted.is_none() && !peer.ip().is_loopback() {
                        refuse(stream, 403);
                        continue;
                    }
                    if workers.len() >= self.0.limits.max_connections {
                        if self.0.hosted.is_none() {
                            refuse(stream, 503);
                        }
                        continue;
                    }
                    if !admitted {
                        if self.0.hosted.is_none() {
                            refuse(stream, 429);
                        }
                        continue;
                    }
                    let state = self.0.clone();
                    let handler = handler.clone();
                    match thread::Builder::new()
                        .name("private-gateway".into())
                        .spawn(move || {
                            connection_with(&state, stream, |state, stream, uncertain| {
                                handler(state, stream, uncertain)
                            })
                        }) {
                        Ok(worker) => workers.push(worker),
                        Err(_) => {
                            failed = true;
                            break;
                        }
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::park_timeout(Duration::from_millis(10))
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => (),
                Err(_) => {
                    failed = true;
                    break;
                }
            }
        }
        drop(listener);
        for worker in workers {
            failed |= worker.join().unwrap_or(true);
        }
        failed |= self.0.unhealthy.load(Ordering::Acquire);
        if failed {
            Err(NetError::Unavailable)
        } else {
            Ok(())
        }
    }
}
/// Catch only unwinding failures whose shared-state boundary can be audited.
/// Configuration/assets are immutable; global and per-client budgets, inflight
/// counts and expiry latches are mutex-protected. A failed lease release also
/// marks shared state unhealthy instead of repairing accounting in place.
/// A panic inside the upstream client may taint its shared TLS internals, so
/// that boundary stays fail-closed even when the admission mutex is healthy.
/// New shared mutable state requires an explicit addition to this audit.
/// Returning true tells the owner to stop admission and drain its workers.
fn connection_with(
    state: &State,
    stream: TcpStream,
    handle: impl FnOnce(&State, TcpStream, &mut bool) -> Result<()>,
) -> bool {
    let mut upstream_uncertain = false;
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        handle(state, stream, &mut upstream_uncertain)
    }));
    // Local request buffers and the socket are dropped on unwind. No failed
    // request is reported as successful and no retained work is acknowledged.
    let unhealthy = upstream_uncertain
        || state.budget.is_poisoned()
        || state
            .hosted
            .as_ref()
            .is_some_and(|hosted| hosted.clients.is_poisoned());
    if unhealthy {
        state.unhealthy.store(true, Ordering::Release);
    }
    // Do not retain or log the payload: it may contain request material.
    // The process-wide panic hook is owned by the embedding executable.
    drop(outcome);
    unhealthy
}
/// Answer an admission refusal with a fixed status on a tightly bounded
/// socket so the accept loop never stalls on an unresponsive peer.
fn refuse(stream: TcpStream, status: u16) {
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_write_timeout(Some(Duration::from_millis(50)));
    let _ = stream.set_read_timeout(Some(Duration::from_millis(50)));
    let mut socket = stream;
    let body = b"temporarily unavailable";
    let _ = socket
        .write_all(
            format!(
                "HTTP/1.1 {status} Result\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n",
                body.len()
            )
            .as_bytes(),
        )
        .and_then(|()| socket.write_all(body));
}
fn admit(state: &State, bytes: usize, request: bool) -> Result<bool> {
    if state.unhealthy.load(Ordering::Acquire) {
        return Err(NetError::Unavailable);
    }
    let mut budget = state.budget.lock().map_err(|_| NetError::Unavailable)?;
    if budget.start.elapsed() >= state.limits.window {
        *budget = Budget {
            start: Instant::now(),
            requests: 0,
            bytes: 0,
        };
    }
    if (request && budget.requests >= state.limits.requests)
        || bytes > state.limits.bytes.saturating_sub(budget.bytes)
    {
        return Ok(false);
    }
    budget.requests += u32::from(request);
    budget.bytes += bytes;
    Ok(true)
}
struct Socket {
    stream: TcpStream,
    deadline: Instant,
}
impl Socket {
    fn remaining(&self) -> std::io::Result<Duration> {
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::TimedOut, "gateway deadline"))
    }
}
impl Read for Socket {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        self.stream.set_read_timeout(Some(self.remaining()?))?;
        self.stream.read(bytes)
    }
}
impl Write for Socket {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.stream.set_write_timeout(Some(self.remaining()?))?;
        self.stream.write(bytes)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.remaining()?;
        self.stream.flush()
    }
}
struct Request {
    method: String,
    path: String,
    headers: BTreeMap<String, String>,
}
fn headers(socket: &mut impl Read) -> Result<Request> {
    let mut raw = Vec::new();
    while !raw.ends_with(b"\r\n\r\n") {
        if raw.len() == HEADER_MAX {
            return Err(NetError::Bounds);
        }
        let mut byte = [0];
        socket
            .read_exact(&mut byte)
            .map_err(|_| NetError::Timeout)?;
        raw.push(byte[0]);
    }
    let text = std::str::from_utf8(&raw).map_err(|_| NetError::Malformed)?;
    if !text.is_ascii() || text.bytes().any(|b| b < 32 && b != b'\r' && b != b'\n') {
        return Err(NetError::Malformed);
    }
    let mut lines = text.split("\r\n");
    let parts: Vec<_> = lines
        .next()
        .ok_or(NetError::Malformed)?
        .split(' ')
        .collect();
    if parts.len() != 3 || parts[2] != "HTTP/1.1" || !parts[1].starts_with('/') {
        return Err(NetError::Malformed);
    }
    let mut headers = BTreeMap::new();
    for line in lines.take_while(|line| !line.is_empty()) {
        let (key, value) = line.split_once(':').ok_or(NetError::Malformed)?;
        if key.is_empty()
            || !key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            || headers.len() == 64
            || headers
                .insert(key.to_ascii_lowercase(), value.trim_matches(' ').to_owned())
                .is_some()
        {
            return Err(NetError::Malformed);
        }
    }
    Ok(Request {
        method: parts[0].to_owned(),
        path: parts[1].to_owned(),
        headers,
    })
}
fn response(socket: &mut impl Write, status: u16, mime: &str, body: &[u8]) -> Result<()> {
    let header = format!(
        "HTTP/1.1 {status} Result\r\nContent-Length: {}\r\nContent-Type: {mime}\r\nConnection: close\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\nCross-Origin-Opener-Policy: same-origin\r\nContent-Security-Policy: {CSP}\r\n\r\n",
        body.len()
    );
    socket
        .write_all(header.as_bytes())
        .and_then(|_| socket.write_all(body))
        .and_then(|_| socket.flush())
        .map_err(|_| NetError::Timeout)
}
#[cfg(test)]
fn handle(state: &State, stream: TcpStream) -> Result<()> {
    handle_tracked(state, stream, &mut false)
}
fn handle_tracked(state: &State, stream: TcpStream, upstream_uncertain: &mut bool) -> Result<()> {
    // BSD/macOS accept inherits the listener's nonblocking mode. Our deadline
    // adapter uses blocking I/O with a freshly bounded timeout per operation;
    // otherwise write_all can stop at a full send buffer and truncate assets.
    stream
        .set_nonblocking(false)
        .map_err(|_| NetError::Unavailable)?;
    let mut socket = Socket {
        stream,
        deadline: Instant::now() + state.limits.timeout,
    };
    let deadline = socket.deadline;
    if let Some(hosted) = &state.hosted {
        socket.deadline = deadline.min(Instant::now() + HANDSHAKE_TIMEOUT);
        let mut connection =
            ServerConnection::new(hosted.tls.clone()).map_err(|_| NetError::Unavailable)?;
        while connection.is_handshaking() {
            connection
                .complete_io(&mut socket)
                .map_err(|_| NetError::Timeout)?;
        }
        if connection.alpn_protocol() != Some(b"http/1.1".as_slice())
            || connection.server_name() != Some(hosted.name.as_str())
        {
            return Err(NetError::Scope);
        }
        socket.deadline = deadline;
        let mut stream = StreamOwned::new(connection, socket);
        handle_request(state, &mut stream, deadline, upstream_uncertain)?;
        stream.conn.send_close_notify();
        return stream.flush().map_err(|_| NetError::Timeout);
    }
    handle_request(state, &mut socket, deadline, upstream_uncertain)
}
fn handle_request(
    state: &State,
    socket: &mut (impl Read + Write),
    deadline: Instant,
    upstream_uncertain: &mut bool,
) -> Result<()> {
    let request = match headers(socket) {
        Ok(value) => value,
        Err(_) => return response(socket, 400, "text/plain", b"request refused"),
    };
    let get = |name: &str| request.headers.get(name).map(String::as_str);
    if get("host") != Some(state.host.as_str()) || get("origin").is_some_and(|v| v != state.origin)
    {
        return response(
            socket,
            403,
            "text/plain",
            if state.hosted.is_some() {
                b"gateway origin refused; use the exact configured host and origin"
            } else {
                b"gateway origin refused; use the configured loopback host and forward the same port"
            },
        );
    }
    if state.hosted.is_some()
        && request.headers.keys().any(|name| {
            name == "forwarded" || name.starts_with("x-forwarded-") || name == "x-real-ip"
        })
    {
        return response(socket, 403, "text/plain", b"request refused");
    }
    if get("transfer-encoding").is_some() || get("content-encoding").is_some() {
        return response(socket, 403, "text/plain", b"request refused");
    }
    if request.method == "GET" {
        if get("content-length").is_some_and(|v| v != "0") {
            return response(socket, 400, "text/plain", b"request refused");
        }
        let path = if request.path == "/" {
            "index.html"
        } else {
            &request.path[1..]
        };
        let Some(body) = state.assets.0.get(path) else {
            return response(socket, 404, "text/plain", b"not found");
        };
        let mime = if path.ends_with(".html") {
            "text/html; charset=utf-8"
        } else if path.ends_with(".js") {
            "text/javascript"
        } else if path.ends_with(".wasm") {
            "application/wasm"
        } else if path.ends_with(".css") {
            "text/css"
        } else {
            "application/octet-stream"
        };
        if !admit(state, body.len(), false)? {
            return response(socket, 429, "text/plain", b"temporarily unavailable");
        }
        return response(socket, 200, mime, body);
    }
    if request.method != "POST"
        || request.path != ENDPOINT
        || get("origin") != Some(state.origin.as_str())
        || get("content-type") != Some("application/octet-stream")
        || get("x-vhalla-namespace").and_then(hex32).as_ref() != Some(state.namespace.as_bytes())
    {
        return response(socket, 403, "text/plain", b"request refused");
    }
    let lease = match authorize(state, get("authorization"))? {
        Authorized::Allowed(lease) => lease,
        Authorized::Denied => return response(socket, 403, "text/plain", b"request refused"),
        Authorized::Busy => return response(socket, 429, "text/plain", b"temporarily unavailable"),
    };
    let length =
        get("content-length").and_then(|v| v.parse::<usize>().ok().filter(|n| n.to_string() == v));
    let Some(length) = length.filter(|n| (5..=MAX_REQUEST + 4).contains(n)) else {
        return response(socket, 400, "text/plain", b"request refused");
    };
    if !admit(state, length, false)?
        || lease
            .as_ref()
            .map(|client| client.charge(length))
            .transpose()?
            .is_some_and(|allowed| !allowed)
    {
        return response(socket, 429, "text/plain", b"temporarily unavailable");
    }
    let mut body = vec![0; length];
    if socket.read_exact(&mut body).is_err() {
        return response(socket, 408, "text/plain", b"request timeout");
    }
    let (op, body) = match decode_frame(&body, MAX_REQUEST) {
        Ok(frame) => frame,
        Err(_) => return response(socket, 400, "text/plain", b"request refused"),
    };
    match op {
        OP_PUT => {
            if !RelayItem::decode(body).is_ok_and(|i| i.namespace() == state.namespace) {
                return response(socket, 400, "text/plain", b"request refused");
            }
        }
        OP_PAGE => {
            if body.len() != 10
                || page_request(
                    u64::from_be_bytes(body[..8].try_into().expect("bounded")),
                    u16::from_be_bytes(body[8..].try_into().expect("bounded")) as usize,
                )
                .is_err()
            {
                return response(socket, 400, "text/plain", b"request refused");
            }
        }
        _ => return response(socket, 400, "text/plain", b"request refused"),
    }
    // The authenticated header may have preceded a slow request body. Recheck
    // the latched wall/monotonic expiry immediately before an upstream effect.
    if lease
        .as_ref()
        .map(ClientLease::live)
        .transpose()?
        .is_some_and(|live| !live)
    {
        return response(socket, 403, "text/plain", b"request refused");
    }
    if Instant::now() >= deadline {
        return Err(NetError::Timeout);
    }
    if state.unhealthy.load(Ordering::Acquire) {
        return Err(NetError::Unavailable);
    }
    *upstream_uncertain = true;
    let exchange = state.upstream.exchange(op, body, deadline);
    *upstream_uncertain = false;
    let (status, body) = match exchange {
        Ok(body) => (STATUS_OK, body),
        Err(error) => (
            match error {
                NetError::Conflict => STATUS_CONFLICT,
                NetError::Capacity => STATUS_CAPACITY,
                NetError::Bounds | NetError::Malformed => STATUS_BOUNDS,
                NetError::Scope => STATUS_SCOPE,
                NetError::Denied => STATUS_DENIED,
                _ => STATUS_UNAVAILABLE,
            },
            Vec::new(),
        ),
    };
    if !admit(state, body.len(), false)?
        || lease
            .as_ref()
            .map(|client| client.charge(body.len() + 5))
            .transpose()?
            .is_some_and(|allowed| !allowed)
    {
        return response(socket, 429, "text/plain", b"temporarily unavailable");
    }
    response(
        socket,
        200,
        "application/octet-stream",
        &frame(status, &body),
    )
}
