use super::*;
use crate::relay::{FileStore, Limits, MAX_RELAY_ITEMS};
use rusqlite::{params, OptionalExtension};
use std::{
    collections::BTreeMap,
    net::{IpAddr, TcpListener},
    sync::{Condvar, Mutex, MutexGuard},
    thread,
};

#[cfg(test)]
#[path = "ledger_tests.rs"]
mod ledger_tests;

/// Transport permissions confer no private-room authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Permissions {
    /// Allow opaque canonical PUTs.
    pub put: bool,
    /// Allow bounded immutable PAGEs.
    pub page: bool,
}
/// An opaque operator-issued key identity. Rotation preserves this identity and
/// its durable quota; a maximum of two explicitly configured tokens may overlap.
/// Removing a token at the next drained restart revokes it. No token is logged.
pub struct Credential {
    /// Stable random operator identity, unrelated to a room or member identity.
    pub id: [u8; 16],
    /// One current token, or current and previous during explicit rotation grace.
    pub tokens: Vec<RelayToken>,
    /// Exactly one independently selected mailbox namespace.
    pub namespace: RelayNamespace,
    /// Explicit PUT/PAGE permissions.
    pub permissions: Permissions,
    /// Immutable retained ciphertext cap within each generation. A migrated
    /// ledger separately enforces cumulative explicitly authorized allowance.
    pub storage: Limits,
    /// Concurrent authenticated operations, including response writes.
    pub max_inflight: usize,
    /// Requests admitted in each service work window.
    pub requests_per_window: u32,
    /// Request bytes plus actual encoded response bytes per service work window.
    pub bytes_per_window: u64,
}
/// Fixed admission limits validated before accepting any connection. Work windows
/// restart with the service; retained storage quotas survive process restart.
/// A peer that is not on this machine is further held to a quarter of the
/// connection slots and a quarter of each window's handshakes, keyed by its
/// IPv4 address or IPv6 /64; loopback peers share only the global bounds.
#[derive(Clone, Copy, Debug)]
pub struct ServiceLimits {
    /// Maximum live handshake/request threads; excess sockets get a bounded
    /// pre-authentication alert refusal, never a silent drop.
    pub max_connections: usize,
    /// One absolute bound covering handshake, frame read, storage admission,
    /// and response. The handshake phase is further capped tighter inside it.
    pub request_timeout: Duration,
    /// Finite fixed-window request/byte accounting period.
    pub window: Duration,
    /// Total authenticated requests per window.
    pub requests_per_window: u32,
    /// Total request plus actual encoded response bytes per window.
    pub bytes_per_window: u64,
    /// Upper bound on how long one authenticated page request may stay open
    /// waiting for newly retained items. Zero disables waiting entirely.
    pub max_wait: Duration,
}
impl Default for ServiceLimits {
    fn default() -> Self {
        Self {
            max_connections: 16,
            request_timeout: Duration::from_secs(10),
            window: Duration::from_secs(1),
            requests_per_window: 128,
            bytes_per_window: 64 * 1024 * 1024,
            max_wait: Duration::from_secs(60),
        }
    }
}
#[derive(Default)]
struct Work {
    requests: u32,
    bytes: u64,
    inflight: usize,
}
struct State {
    store: FileStore,
    credentials: Vec<Credential>,
    limits: ServiceLimits,
    window_start: Instant,
    global: Work,
    keys: BTreeMap<[u8; 16], Work>,
    poisoned: bool,
    ledger_format: u8,
}
/// An explicitly enrolled, single-namespace durable mailbox service. Item
/// publication and its per-key storage charge commit in one SQLite transaction
/// behind a single post-commit durability barrier. Socket reads/writes never
/// hold the mailbox mutex. Finite credential work and in-flight caps prevent
/// one authenticated key from using every service slot. Pre-authentication
/// work is bounded four ways: worker count, handshakes per window, per-source
/// shares of both for peers that are not on this machine, and a
/// handshake-phase deadline tighter than the whole request; over-limit
/// sockets get a bounded fatal alert instead of a silent drop.
/// An admitted page request may also wait up to `max_wait` for a committed
/// put; committed put responses wake waiting page workers on `notify`, and
/// each waiter still occupies its connection, in-flight and window shares.
pub struct Service {
    state: Arc<Mutex<State>>,
    config: Arc<ServerConfig>,
    notify: Arc<Condvar>,
}

impl Service {
    /// Explicitly enroll an EMPTY mailbox for TLS admission. Existing or used
    /// enrollments refuse. Never infer the owner of legacy retained ciphertext.
    pub fn initialize(store: FileStore) -> Result<()> {
        store.live().map_err(|_| NetError::Unavailable)?;
        if store.fenced().map_err(|_| NetError::Unavailable)? {
            return Err(NetError::Conflict);
        }
        let count: i64 = store
            .conn
            .query_row("SELECT COUNT(*) FROM items", [], |r| r.get(0))
            .map_err(|_| NetError::Unavailable)?;
        if count != 0 {
            return Err(NetError::Conflict);
        }
        store.conn.execute_batch("BEGIN IMMEDIATE;
            CREATE TABLE tls_keys (id BLOB PRIMARY KEY CHECK(length(id)=16), max_items INTEGER NOT NULL, max_bytes INTEGER NOT NULL);
            CREATE TABLE tls_charges (digest BLOB PRIMARY KEY CHECK(length(digest)=32), key_id BLOB NOT NULL REFERENCES tls_keys(id), bytes INTEGER NOT NULL);
            CREATE INDEX tls_charges_by_key ON tls_charges(key_id);
            CREATE TABLE tls_meta (id INTEGER PRIMARY KEY CHECK(id=1), format INTEGER NOT NULL CHECK(format=1));
            INSERT INTO tls_meta VALUES(1,1);
            COMMIT;").map_err(|_| NetError::Unavailable)?;
        store.sync().map_err(|_| NetError::Unavailable)
    }
    /// Open an enrolled mailbox under an immutable startup configuration. Token
    /// replacement and permission revocation take effect only after the previous
    /// server is drained/stopped; the mailbox lifetime lock excludes two owners.
    pub fn new(
        store: FileStore,
        config: Arc<ServerConfig>,
        credentials: Vec<Credential>,
        limits: ServiceLimits,
    ) -> Result<Self> {
        if !(2..=64).contains(&limits.max_connections)
            || limits.request_timeout.is_zero()
            || limits.request_timeout > Duration::from_secs(30)
            || limits.window.is_zero()
            || limits.window > Duration::from_secs(60)
            || limits.requests_per_window < 2
            || limits.requests_per_window > 1_000_000
            || limits.bytes_per_window < 2
            || limits.bytes_per_window > 1024 * 1024 * 1024
            || limits.max_wait > Duration::from_secs(120)
            || credentials.is_empty()
            || credentials.len() > 64
            || config.max_early_data_size != 0
        {
            return Err(NetError::Bounds);
        }
        let mut ids = std::collections::BTreeSet::new();
        let mut tokens = std::collections::BTreeSet::new();
        for c in &credentials {
            if c.id == [0; 16]
                || !ids.insert(c.id)
                || c.namespace != store.namespace()
                || c.tokens.is_empty()
                || c.tokens.len() > 2
                || (!c.permissions.put && !c.permissions.page)
                || c.storage.max_items == 0
                || c.storage.max_items > MAX_RELAY_ITEMS
                || c.storage.max_bytes == 0
                || c.storage.max_bytes > store.limits.max_bytes / 2
                || c.storage.max_items > store.limits.max_items / 2
                || c.max_inflight == 0
                || c.max_inflight > limits.max_connections / 2
                || c.requests_per_window == 0
                || c.requests_per_window > limits.requests_per_window / 2
                || c.bytes_per_window == 0
                || c.bytes_per_window > limits.bytes_per_window / 2
                || c.tokens.iter().any(|t| !tokens.insert(*t.as_bytes()))
            {
                return Err(NetError::Bounds);
            }
        }
        let ledger_format = ledger::validate(&store)?;
        // Per-key quota scans must not grow with every retained item. Stores
        // enrolled before this index existed are repaired once, idempotently.
        store
            .conn
            .execute_batch("CREATE INDEX IF NOT EXISTS tls_charges_by_key ON tls_charges(key_id)")
            .map_err(|_| NetError::Unavailable)?;
        let count: i64 = store
            .conn
            .query_row("SELECT COUNT(*) FROM tls_keys", [], |r| r.get(0))
            .map_err(|_| NetError::Unavailable)?;
        // New credential identities are an explicit operator admission; quotas
        // already associated with an identity can never reset or change here.
        let mut additions = Vec::new();
        for c in &credentials {
            let prior: Option<(i64, i64)> = store
                .conn
                .query_row(
                    "SELECT max_items,max_bytes FROM tls_keys WHERE id=?1",
                    params![c.id.as_slice()],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()
                .map_err(|_| NetError::Unavailable)?;
            let wanted = (
                c.storage.max_items as i64,
                i64::try_from(c.storage.max_bytes).map_err(|_| NetError::Bounds)?,
            );
            match prior {
                Some(actual) if actual != wanted => return Err(NetError::Conflict),
                Some(_) => (),
                None => additions.push((c.id, wanted)),
            }
        }
        if count as usize + additions.len() > 64 {
            return Err(NetError::Capacity);
        }
        // The fence also freezes the exported quota basis. Existing identities
        // may replace tokens; enrolling another identity would alter that basis.
        if !additions.is_empty() && store.fenced().map_err(|_| NetError::Unavailable)? {
            return Err(NetError::Conflict);
        }
        store
            .conn
            .execute_batch("BEGIN IMMEDIATE")
            .map_err(|_| NetError::Unavailable)?;
        for (id, (max_items, max_bytes)) in additions {
            store
                .conn
                .execute(
                    "INSERT INTO tls_keys VALUES(?1,?2,?3)",
                    params![id.as_slice(), max_items, max_bytes],
                )
                .map_err(|_| NetError::Unavailable)?;
            if ledger_format == 2 {
                store
                    .conn
                    .execute(
                        "INSERT INTO tls_budget VALUES(?1,0,0,?2,?3,0)",
                        params![id.as_slice(), max_items, max_bytes],
                    )
                    .map_err(|_| NetError::Unavailable)?;
            }
        }
        store
            .conn
            .execute_batch("COMMIT")
            .map_err(|_| NetError::Unavailable)?;
        store.sync().map_err(|_| NetError::Unavailable)?;
        let mut selected = (*config).clone();
        selected.alpn_protocols = vec![protocol(store.namespace())];
        let config = Arc::new(selected);
        Ok(Self {
            notify: Arc::new(Condvar::new()),
            state: Arc::new(Mutex::new(State {
                store,
                credentials,
                limits,
                window_start: Instant::now(),
                global: Work::default(),
                keys: BTreeMap::new(),
                poisoned: false,
                ledger_format,
            })),
            config,
        })
    }
    /// Serve one bounded request per connection. `limit` bounds accepted sockets
    /// for qualification or supervised finite runs. Durable uncertainty or a
    /// worker panic stops admission and returns Unavailable after owned workers
    /// drain under their original deadlines. No additional client is required
    /// to wake the supervisor; no detached worker retains mailbox custody.
    pub fn serve(self, listener: TcpListener, limit: Option<u64>) -> Result<()> {
        self.serve_until(
            listener,
            limit,
            Arc::new(std::sync::atomic::AtomicBool::new(false)),
        )
    }

    /// Serve until the selected external stop flag is set. Shutdown stops new
    /// admission within the bounded accept poll and drains already admitted
    /// workers under their original request deadlines before releasing custody.
    /// Storage uncertainty still returns an error; stopping never resets it.
    pub fn serve_until(
        self,
        listener: TcpListener,
        limit: Option<u64>,
        stop: Arc<std::sync::atomic::AtomicBool>,
    ) -> Result<()> {
        let (max, timeout, window, max_handshakes) = {
            let s = self.state.lock().map_err(|_| NetError::Unavailable)?;
            (
                s.limits.max_connections,
                s.limits.request_timeout,
                s.limits.window,
                s.limits.requests_per_window.saturating_mul(2),
            )
        };
        listener
            .set_nonblocking(true)
            .map_err(|_| NetError::Unavailable)?;
        // Workers watch this rather than the caller's stop flag: a finite
        // `serve` limit or a failure ends admission without setting it, and
        // held page waits must still answer promptly while draining.
        let draining = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut workers: Vec<(thread::JoinHandle<()>, Option<IpAddr>)> = Vec::new();
        let mut sources = Sources::new(max, max_handshakes);
        let mut accepted = 0u64;
        let mut window_start = Instant::now();
        let mut handshakes = 0u32;
        let mut failure = None;
        while !stop.load(std::sync::atomic::Ordering::Acquire) && limit.is_none_or(|n| accepted < n)
        {
            // Never block admission on the mailbox mutex or accept(): a failed
            // worker wakes this supervisor, even when no further client arrives.
            if self.unhealthy() {
                failure = Some(NetError::Unavailable);
                break;
            }
            let mut index = 0;
            while index < workers.len() {
                if workers[index].0.is_finished() {
                    let (worker, remote) = workers.swap_remove(index);
                    if let Some(remote) = remote {
                        sources.release(remote);
                    }
                    if worker.join().is_err() {
                        failure = Some(NetError::Unavailable);
                    }
                } else {
                    index += 1;
                }
            }
            if failure.is_some() {
                break;
            }
            let (stream, peer) = match listener.accept() {
                Ok(pair) => pair,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    // A finite park handles a panic before the worker's explicit
                    // wake, and closes the race between checking and accepting.
                    thread::park_timeout(Duration::from_millis(20));
                    continue;
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => {
                    failure = Some(NetError::Unavailable);
                    break;
                }
            };
            accepted += 1;
            if window_start.elapsed() >= window {
                window_start = Instant::now();
                handshakes = 0;
                sources.next_window();
            }
            // The per-source share is charged only once the global bounds admit
            // the socket, so a refusal never consumes a source's allowance. The
            // failure paths below end admission; any path that continues after a
            // charge must release it.
            let remote = remote_source(peer.ip());
            if workers.len() >= max
                || handshakes >= max_handshakes
                || remote.is_some_and(|remote| !sources.admit(remote))
            {
                refuse(stream);
                continue;
            }
            // Accepted descriptors need blocking I/O plus DeadlineSocket's
            // remaining timeout on every syscall, on every supported Unix host.
            if stream.set_nonblocking(false).is_err() {
                failure = Some(NetError::Unavailable);
                break;
            }
            handshakes += 1;
            let state = self.state.clone();
            let config = self.config.clone();
            let notify = self.notify.clone();
            let stopped = draining.clone();
            let deadline = Instant::now() + timeout;
            let supervisor = thread::current();
            match thread::Builder::new()
                .name("vhalla-relay-tls".into())
                .spawn(move || {
                    let _ = serve_one(stream, config, state, notify, stopped, deadline);
                    supervisor.unpark();
                }) {
                Ok(worker) => workers.push((worker, remote)),
                Err(_) => {
                    failure = Some(NetError::Unavailable);
                    break;
                }
            }
        }
        // Close the listening endpoint before draining existing deadline-bound
        // sockets. A poisoned service cannot keep admitting a false healthy route.
        drop(listener);
        // Held page waits answer their current page instead of keeping the
        // drain waiting on their expiry.
        draining.store(true, std::sync::atomic::Ordering::Release);
        self.notify.notify_all();
        for (worker, _) in workers {
            if worker.join().is_err() {
                failure = Some(NetError::Unavailable);
            }
        }
        if self.unhealthy() {
            failure = Some(NetError::Unavailable);
        }
        failure.map_or(Ok(()), Err)
    }
    fn unhealthy(&self) -> bool {
        match self.state.try_lock() {
            Ok(state) => state.poisoned,
            Err(std::sync::TryLockError::Poisoned(_)) => true,
            Err(std::sync::TryLockError::WouldBlock) => false,
        }
    }
}
/// The TLS handshake phase is bounded tighter than the whole request so a
/// slowly trickling ClientHello cannot occupy a worker for `request_timeout`.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(4);
/// Most distinct remote sources counted in one window. A new source beyond it
/// is refused until the window turns, so a spread-out flood cannot grow the
/// table without bound.
const MAX_TRACKED_SOURCES: usize = 4096;
/// Per-source shares for peers that are not on this machine: each may hold a
/// quarter of the connection slots and start a quarter of a window's
/// handshakes, so one misbehaving machine cannot occupy the whole service.
struct Sources {
    live_limit: usize,
    window_limit: u32,
    live: BTreeMap<IpAddr, usize>,
    started: BTreeMap<IpAddr, u32>,
}
impl Sources {
    fn new(max_connections: usize, max_handshakes: u32) -> Self {
        Self {
            live_limit: (max_connections / 4).max(1),
            window_limit: (max_handshakes / 4).max(1),
            live: BTreeMap::new(),
            started: BTreeMap::new(),
        }
    }
    /// Charge one handshake to `source`, or refuse without charging it.
    fn admit(&mut self, source: IpAddr) -> bool {
        let started = self.started.get(&source).copied().unwrap_or(0);
        if self.live.get(&source).copied().unwrap_or(0) >= self.live_limit
            || started >= self.window_limit
            || (started == 0 && self.started.len() >= MAX_TRACKED_SOURCES)
        {
            return false;
        }
        *self.live.entry(source).or_default() += 1;
        *self.started.entry(source).or_default() += 1;
        true
    }
    /// Return the slot of a finished worker admitted for `source`.
    fn release(&mut self, source: IpAddr) {
        if let Some(live) = self.live.get_mut(&source) {
            *live = live.saturating_sub(1);
            if *live == 0 {
                self.live.remove(&source);
            }
        }
    }
    fn next_window(&mut self) {
        self.started.clear();
    }
}
/// The per-source key for a peer, or `None` for this machine. Loopback peers,
/// which include an overlay forward that terminates here, share only the
/// global bounds. IPv4-mapped IPv6 peers count as IPv4; other IPv6 peers group
/// by /64 because one network usually controls a whole /64.
fn remote_source(peer: IpAddr) -> Option<IpAddr> {
    match peer.to_canonical() {
        ip if ip.is_loopback() => None,
        IpAddr::V6(ip) => {
            let mut octets = ip.octets();
            octets[8..].fill(0);
            Some(IpAddr::V6(octets.into()))
        }
        ip => Some(ip),
    }
}
/// Answer an over-limit pre-authentication socket with a bounded fatal
/// internal_error alert, then release it. A real client reads an explicit
/// retryable refusal instead of silence; the tight timeouts prevent an
/// unresponsive peer from stalling the accept loop.
fn refuse(stream: TcpStream) {
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(Duration::from_millis(50)));
    let _ = stream.set_write_timeout(Some(Duration::from_millis(50)));
    let mut socket = stream;
    // TLS alert record: fatal internal_error — the only refusal legible to a
    // client before any negotiated keys exist.
    let _ = socket.write_all(&[0x15, 0x03, 0x01, 0x00, 0x02, 0x02, 0x50]);
}
fn token_matches(token: &RelayToken, raw: &[u8]) -> bool {
    raw.len() == 32
        && token
            .as_bytes()
            .iter()
            .zip(raw)
            .fold(0u8, |diff, (a, b)| diff | (a ^ b))
            == 0
}
struct Admission {
    state: Arc<Mutex<State>>,
    id: [u8; 16],
}
impl Drop for Admission {
    fn drop(&mut self) {
        if let Ok(mut s) = self.state.lock() {
            if let Some(key) = s.keys.get_mut(&self.id) {
                key.inflight = key.inflight.saturating_sub(1);
            }
        }
    }
}
fn serve_one(
    stream: TcpStream,
    config: Arc<ServerConfig>,
    state: Arc<Mutex<State>>,
    notify: Arc<Condvar>,
    draining: Arc<std::sync::atomic::AtomicBool>,
    deadline: Instant,
) -> Result<()> {
    // The pre-authentication phase gets a tighter bound than the whole
    // request; a completed handshake keeps the original absolute deadline.
    let mut socket = DeadlineSocket {
        stream,
        deadline: deadline.min(Instant::now() + HANDSHAKE_TIMEOUT),
    };
    let expected_protocol = config
        .alpn_protocols
        .first()
        .cloned()
        .ok_or(NetError::Bounds)?;
    let mut connection =
        rustls::ServerConnection::new(config).map_err(|_| NetError::Unavailable)?;
    while connection.is_handshaking() {
        connection.complete_io(&mut socket).map_err(io)?;
    }
    if connection.alpn_protocol() != Some(expected_protocol.as_slice()) {
        return Err(NetError::Scope);
    }
    socket.deadline = deadline;
    let mut tls = StreamOwned::new(connection, socket);
    let request = read_frame(&mut tls, MAX_REQUEST, deadline)?;
    if request.len() < 33 {
        return write_frame(&mut tls, STATUS_DENIED, &[], deadline);
    }
    let mut s = state.lock().map_err(|_| NetError::Unavailable)?;
    remaining(deadline).map_err(io)?;
    if s.poisoned {
        return Err(NetError::Unavailable);
    }
    let Some(index) = s
        .credentials
        .iter()
        .position(|c| c.tokens.iter().any(|t| token_matches(t, &request[1..33])))
    else {
        drop(s);
        return write_frame(&mut tls, STATUS_DENIED, &[], deadline);
    };
    let c = &s.credentials[index];
    if (request[0] == OP_PUT && !c.permissions.put)
        || (request[0] == OP_PAGE && !c.permissions.page)
    {
        drop(s);
        return write_frame(&mut tls, STATUS_DENIED, &[], deadline);
    }
    let (id, max_inflight, max_requests, max_bytes) = (
        c.id,
        c.max_inflight,
        c.requests_per_window,
        c.bytes_per_window,
    );
    if s.window_start.elapsed() >= s.limits.window {
        s.window_start = Instant::now();
        s.global.requests = 0;
        s.global.bytes = 0;
        for key in s.keys.values_mut() {
            key.requests = 0;
            key.bytes = 0;
        }
    }
    // Admission bills the request frame now; the response is charged on its
    // actual encoded size after dispatch, so a small PAGE answer does not burn
    // a worst-case reservation against this work window.
    let bytes = request.len() as u64 + 4;
    let global_full = s.global.requests >= s.limits.requests_per_window
        || s.global.bytes.saturating_add(bytes) > s.limits.bytes_per_window;
    let key = s.keys.entry(id).or_default();
    if global_full
        || key.inflight >= max_inflight
        || key.requests >= max_requests
        || key.bytes.saturating_add(bytes) > max_bytes
    {
        drop(s);
        return write_frame(&mut tls, STATUS_CAPACITY, &[], deadline);
    }
    key.inflight += 1;
    key.requests += 1;
    key.bytes += bytes;
    s.global.requests += 1;
    s.global.bytes += bytes;
    let admitted = Admission {
        state: state.clone(),
        id,
    };
    let mut reply_deadline = deadline;
    let response = if request[0] == OP_PUT {
        put(&mut s, id, &request[33..])
    } else if let Some((after, limit, wait_ms)) = page_wait_fields(&request) {
        // A held page keeps its admitted slot and this request's charges for
        // the whole bounded wait; the response gets a fresh write reserve
        // because the original deadline may already have elapsed.
        let until =
            Instant::now() + Duration::from_millis(u64::from(wait_ms)).min(s.limits.max_wait);
        reply_deadline = until + WRITE_RESERVE;
        tls.sock.deadline = reply_deadline;
        let (guard, outcome) = waited_page(s, &notify, &draining, after, limit, until);
        s = guard;
        outcome
    } else {
        dispatch(&mut s.store, request[0], &request[33..])
    };
    if response
        .as_ref()
        .is_err_and(|e| *e == NetError::Unavailable)
        || response
            .as_ref()
            .is_ok_and(|(code, _)| *code == STATUS_UNAVAILABLE)
    {
        s.poisoned = true;
    }
    drop(s);
    // A put commits or refutes under the same lock the waiters re-read; wake
    // them only after releasing it so they do not park straight back on it.
    if request[0] == OP_PUT {
        notify.notify_all();
    }
    let (code, body) = response?;
    // Bill the exact response frame now that its size is known. One admitted
    // response may exceed the window by at most its own bounded size; later
    // requests see the spent budget and answer capacity.
    if let Ok(mut s) = state.lock() {
        let billed = body.len() as u64 + 5;
        if let Some(key) = s.keys.get_mut(&id) {
            key.bytes = key.bytes.saturating_add(billed);
        }
        s.global.bytes = s.global.bytes.saturating_add(billed);
    }
    let result = write_frame(&mut tls, code, &body, reply_deadline);
    drop(admitted);
    result
}
/// A condvar wake under a held page is a local re-check, not a wire exchange:
/// capping each step this way keeps a stop flag or poisoned state observable
/// on a quiet mailbox even without a notifying put.
const WAIT_WAKE: Duration = Duration::from_secs(10);
/// Socket budget reserved for writing a waited page's response after the hold
/// itself ends; the request's own deadline may already have elapsed by then.
const WRITE_RESERVE: Duration = Duration::from_secs(5);
/// Decode the extra two-byte wait bound on a 12-byte page request. Any other
/// body length stays on the ordinary path and draws the canonical refusal.
fn page_wait_fields(request: &[u8]) -> Option<(u64, usize, u16)> {
    if request.len() == 45 && request[0] == OP_PAGE {
        Some((
            u64::from_be_bytes(request[33..41].try_into().expect("bounded")),
            u16::from_be_bytes(request[41..43].try_into().expect("bounded")) as usize,
            u16::from_be_bytes(request[43..45].try_into().expect("bounded")),
        ))
    } else {
        None
    }
}
/// Answer a page request that asked to be held open. The mailbox is re-read
/// under the shared mutex until records appear, the bounded wait expires, the
/// service stops, or another worker poisons it; every iteration stays inside
/// the caller's admitted slot and each wait step remains bounded.
fn waited_page<'a>(
    s: MutexGuard<'a, State>,
    notify: &Condvar,
    draining: &std::sync::atomic::AtomicBool,
    after: u64,
    limit: usize,
    until: Instant,
) -> (MutexGuard<'a, State>, Result<(u8, Vec<u8>)>) {
    let mut s = s;
    loop {
        match s.store.page(after, limit) {
            Err(error) => return (s, Ok((status(error), Vec::new()))),
            Ok(page) => {
                // A poisoned mailbox fails closed: another worker already saw
                // durable uncertainty, so this page cannot be trusted as new.
                if s.poisoned {
                    return (s, Err(NetError::Unavailable));
                }
                let remaining = until.saturating_duration_since(Instant::now());
                if !page.records.is_empty()
                    || remaining.is_zero()
                    || draining.load(std::sync::atomic::Ordering::Acquire)
                {
                    return (s, encode_page(&page).map(|body| (STATUS_OK, body)));
                }
                match notify.wait_timeout(s, remaining.min(WAIT_WAKE)) {
                    Ok((guard, _)) => s = guard,
                    // A poisoned mutex still yields its guard so the caller's
                    // own poison check keeps working; the request fails closed.
                    Err(poisoned) => {
                        return (poisoned.into_inner().0, Err(NetError::Unavailable));
                    }
                }
            }
        }
    }
}
fn put(state: &mut State, id: [u8; 16], raw: &[u8]) -> Result<(u8, Vec<u8>)> {
    let item = match RelayItem::decode(raw) {
        Ok(item) => item,
        Err(error) => return Ok((status(error), Vec::new())),
    };
    if item.namespace() != state.store.namespace() {
        return Ok((STATUS_SCOPE, Vec::new()));
    }
    let store = &mut state.store;
    store
        .conn
        .execute_batch("BEGIN IMMEDIATE")
        .map_err(|_| NetError::Unavailable)?;
    let outcome = (|| {
        let charged: bool = store
            .conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM tls_charges WHERE digest=?1)",
                params![item.digest().as_slice()],
                |r| r.get(0),
            )
            .map_err(|_| super::super::Error::Storage)?;
        if !charged {
            let size =
                i64::try_from(item.payload().len()).map_err(|_| super::super::Error::Bounds)?;
            ledger::charge(store, state.ledger_format, id, size)?;
            store
                .conn
                .execute(
                    "INSERT INTO tls_charges VALUES(?1,?2,?3)",
                    params![item.digest().as_slice(), id.as_slice(), size],
                )
                .map_err(|_| super::super::Error::Storage)?;
        }
        store.put_staged(item)
    })();
    match outcome {
        Ok(receipt) => {
            store
                .conn
                .execute_batch("COMMIT")
                .map_err(|_| NetError::Unavailable)?;
            store.sync().map_err(|_| NetError::Unavailable)?;
            let mut body = receipt.position.to_be_bytes().to_vec();
            body.extend_from_slice(&receipt.digest);
            body.push(u8::from(receipt.duplicate));
            Ok((STATUS_OK, body))
        }
        Err(error) => {
            store
                .conn
                .execute_batch("ROLLBACK")
                .map_err(|_| NetError::Unavailable)?;
            if error == super::super::Error::Storage {
                return Err(NetError::Unavailable);
            }
            Ok((status(error), Vec::new()))
        }
    }
}

#[cfg(test)]
mod source_tests {
    use super::*;
    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn loopback_peers_are_exempt_and_remote_ipv6_groups_by_its_64() {
        for local in ["127.0.0.1", "127.5.6.7", "::1", "::ffff:127.0.0.1"] {
            assert_eq!(remote_source(ip(local)), None, "{local}");
        }
        assert_eq!(remote_source(ip("192.168.1.20")), Some(ip("192.168.1.20")));
        assert_eq!(
            remote_source(ip("::ffff:192.168.1.20")),
            Some(ip("192.168.1.20"))
        );
        assert_eq!(
            remote_source(ip("2001:db8:1:2:aaaa:bbbb:cccc:dddd")),
            Some(ip("2001:db8:1:2::"))
        );
        assert_eq!(
            remote_source(ip("2001:db8:1:2::9")),
            remote_source(ip("2001:db8:1:2:ffff::1"))
        );
        assert_ne!(
            remote_source(ip("2001:db8:1:2::9")),
            remote_source(ip("2001:db8:1:3::9"))
        );
    }

    #[test]
    fn shares_are_a_quarter_of_the_global_bounds_and_never_zero() {
        let default = Sources::new(16, 256);
        assert_eq!((default.live_limit, default.window_limit), (4, 64));
        let smallest = Sources::new(2, 4);
        assert_eq!((smallest.live_limit, smallest.window_limit), (1, 1));
    }

    #[test]
    fn one_source_holds_at_most_its_share_and_released_slots_return() {
        let mut sources = Sources::new(8, 1024);
        let (a, b) = (ip("198.51.100.1"), ip("198.51.100.2"));
        assert!(sources.admit(a) && sources.admit(a));
        assert!(
            !sources.admit(a),
            "a third live connection exceeds the share"
        );
        assert!(sources.admit(b), "another source keeps its own share");
        sources.release(a);
        assert!(sources.admit(a));
        sources.release(a);
        sources.release(a);
        sources.release(b);
        assert!(sources.live.is_empty(), "finished workers leave no entries");
    }

    #[test]
    fn handshakes_per_window_are_charged_per_source_until_the_window_turns() {
        let mut sources = Sources::new(64, 16);
        let (a, b) = (ip("198.51.100.1"), ip("198.51.100.2"));
        for _ in 0..4 {
            assert!(sources.admit(a));
            sources.release(a);
        }
        assert!(
            !sources.admit(a),
            "a fifth handshake exceeds the window share"
        );
        assert!(!sources.live.contains_key(&a), "a refusal charges nothing");
        assert!(sources.admit(b));
        sources.next_window();
        assert!(sources.admit(a));
    }

    #[test]
    fn new_sources_are_refused_once_the_window_table_is_full() {
        let mut sources = Sources::new(64, u32::MAX);
        let numbered = |n: u32| IpAddr::V4(std::net::Ipv4Addr::from(0x0a00_0000 + n));
        for index in 0..MAX_TRACKED_SOURCES as u32 {
            assert!(sources.admit(numbered(index)));
            sources.release(numbered(index));
        }
        let known = numbered(0);
        let unknown = ip("203.0.113.9");
        assert!(sources.admit(known), "a counted source keeps its allowance");
        assert!(!sources.admit(unknown));
        sources.next_window();
        assert!(sources.admit(unknown));
    }
}
