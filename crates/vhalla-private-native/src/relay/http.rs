//! Loopback-only, same-origin browser gateway to explicitly selected TLS relays.
//! No mailbox is opened here. Admission precedes upstream network effects.
use super::{codec::*, net::NetError, tls::TlsRelay, RelayItem, RelayNamespace};
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
    time::{Duration, Instant},
};
#[cfg(test)]
mod tests;
type Result<T> = std::result::Result<T, NetError>;
const HEADER_MAX: usize = 8192;
/// Fixed HTTP endpoint; callers cannot choose an upstream address.
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
    routes: BTreeMap<[u8; 32], Route>,
    limits: GatewayLimits,
    assets: Assets,
    budget: Mutex<Budget>,
    unhealthy: AtomicBool,
}
struct Route {
    capability: BrowserCapability,
    upstream: Arc<dyn Upstream>,
}
/// One immutable operator-selected route. A browser selects only its namespace;
/// it can never supply a network address, TLS name, credential or redirect.
pub struct GatewayRoute {
    namespace: RelayNamespace,
    capability: BrowserCapability,
    upstream: TlsRelay,
}
impl GatewayRoute {
    /// Keep a separate browser capability and the exact pinned TLS profile.
    pub fn new(
        namespace: RelayNamespace,
        capability: BrowserCapability,
        upstream: TlsRelay,
    ) -> Result<Self> {
        if upstream.token_matches(&capability.0) {
            return Err(NetError::Denied);
        }
        if upstream.namespace() != namespace {
            return Err(NetError::Scope);
        }
        Ok(Self {
            namespace,
            capability,
            upstream,
        })
    }
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
        Self::with_routes(
            address,
            vec![GatewayRoute::new(namespace, capability, upstream)?],
            assets,
            limits,
        )
    }
    /// Retain up to sixteen exact generations at one stable browser origin.
    /// All routes share admission budgets and shutdown custody. A predecessor's
    /// TLS host enforces its permanent fence; this gateway cannot unfence it.
    pub fn with_routes(
        address: SocketAddr,
        routes: Vec<GatewayRoute>,
        assets: Assets,
        limits: GatewayLimits,
    ) -> Result<Self> {
        if routes.is_empty() || routes.len() > 16 {
            return Err(NetError::Bounds);
        }
        // No browser capability may disclose any route's upstream credential.
        for (index, route) in routes.iter().enumerate() {
            if routes
                .iter()
                .any(|other| other.upstream.token_matches(&route.capability.0))
            {
                return Err(NetError::Denied);
            }
            if routes[..index]
                .iter()
                .any(|other| other.capability.0 == route.capability.0)
            {
                return Err(NetError::Conflict);
            }
        }
        let mut selected = BTreeMap::new();
        for route in routes {
            if selected
                .insert(
                    *route.namespace.as_bytes(),
                    Route {
                        capability: route.capability,
                        upstream: Arc::new(route.upstream),
                    },
                )
                .is_some()
            {
                return Err(NetError::Conflict);
            }
        }
        Self::configured_routes(address, selected, assets, limits)
    }
    #[cfg(test)]
    fn configured(
        address: SocketAddr,
        namespace: RelayNamespace,
        capability: BrowserCapability,
        upstream: Arc<dyn Upstream>,
        assets: Assets,
        limits: GatewayLimits,
    ) -> Result<Self> {
        Self::configured_routes(
            address,
            BTreeMap::from([(
                *namespace.as_bytes(),
                Route {
                    capability,
                    upstream,
                },
            )]),
            assets,
            limits,
        )
    }
    fn configured_routes(
        address: SocketAddr,
        routes: BTreeMap<[u8; 32], Route>,
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
            routes,
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
    /// Stable browser origin, always numeric loopback HTTP.
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
                    if !peer.ip().is_loopback() {
                        refuse(stream, 403);
                        continue;
                    }
                    if workers.len() >= self.0.limits.max_connections {
                        refuse(stream, 503);
                        continue;
                    }
                    if !admitted {
                        refuse(stream, 429);
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
/// Configuration/assets are immutable; budget mutation is mutex-protected.
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
    let unhealthy = upstream_uncertain || state.budget.is_poisoned();
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
fn headers(socket: &mut Socket) -> Result<Request> {
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
fn response(socket: &mut Socket, status: u16, mime: &str, body: &[u8]) -> Result<()> {
    let header = format!(
        "HTTP/1.1 {status} Result\r\nContent-Length: {}\r\nContent-Type: {mime}\r\nConnection: close\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\nCross-Origin-Opener-Policy: same-origin\r\nContent-Security-Policy: {CSP}\r\n\r\n",
        body.len()
    );
    socket
        .write_all(header.as_bytes())
        .and_then(|_| socket.write_all(body))
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
    let request = match headers(&mut socket) {
        Ok(value) => value,
        Err(_) => return response(&mut socket, 400, "text/plain", b"request refused"),
    };
    let get = |name: &str| request.headers.get(name).map(String::as_str);
    if get("host") != Some(state.host.as_str()) || get("origin").is_some_and(|v| v != state.origin)
    {
        return response(
            &mut socket,
            403,
            "text/plain",
            b"gateway origin refused; use the configured loopback host and forward the same port",
        );
    }
    if get("transfer-encoding").is_some() || get("content-encoding").is_some() {
        return response(&mut socket, 403, "text/plain", b"request refused");
    }
    if request.method == "GET" {
        if get("content-length").is_some_and(|v| v != "0") {
            return response(&mut socket, 400, "text/plain", b"request refused");
        }
        let path = if request.path == "/" {
            "index.html"
        } else {
            &request.path[1..]
        };
        let Some(body) = state.assets.0.get(path) else {
            return response(&mut socket, 404, "text/plain", b"not found");
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
            return response(&mut socket, 429, "text/plain", b"temporarily unavailable");
        }
        return response(&mut socket, 200, mime, body);
    }
    if request.method != "POST"
        || request.path != ENDPOINT
        || get("origin") != Some(state.origin.as_str())
        || get("content-type") != Some("application/octet-stream")
    {
        return response(&mut socket, 403, "text/plain", b"request refused");
    }
    let selected = get("x-vhalla-namespace").and_then(hex32);
    let Some((namespace, route)) = selected
        .as_ref()
        .and_then(|id| state.routes.get_key_value(id))
    else {
        return response(&mut socket, 403, "text/plain", b"request refused");
    };
    if !get("authorization").is_some_and(|value| route.capability.matches(value)) {
        return response(&mut socket, 403, "text/plain", b"request refused");
    }
    let length =
        get("content-length").and_then(|v| v.parse::<usize>().ok().filter(|n| n.to_string() == v));
    let Some(length) = length.filter(|n| (5..=MAX_REQUEST + 4).contains(n)) else {
        return response(&mut socket, 400, "text/plain", b"request refused");
    };
    if !admit(state, length, false)? {
        return response(&mut socket, 429, "text/plain", b"temporarily unavailable");
    }
    let mut body = vec![0; length];
    if socket.read_exact(&mut body).is_err() {
        return response(&mut socket, 408, "text/plain", b"request timeout");
    }
    let (op, body) = match decode_frame(&body, MAX_REQUEST) {
        Ok(frame) => frame,
        Err(_) => return response(&mut socket, 400, "text/plain", b"request refused"),
    };
    match op {
        OP_PUT => {
            if !RelayItem::decode(body).is_ok_and(|i| i.namespace().as_bytes() == namespace) {
                return response(&mut socket, 400, "text/plain", b"request refused");
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
                return response(&mut socket, 400, "text/plain", b"request refused");
            }
        }
        _ => return response(&mut socket, 400, "text/plain", b"request refused"),
    }
    *upstream_uncertain = true;
    let exchange = route.upstream.exchange(op, body, socket.deadline);
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
    if !admit(state, body.len(), false)? {
        return response(&mut socket, 429, "text/plain", b"temporarily unavailable");
    }
    response(
        &mut socket,
        200,
        "application/octet-stream",
        &frame(status, &body),
    )
}
