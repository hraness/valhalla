use super::*;
use crate::relay::{FileStore, Limits, MAX_RELAY_ITEMS};
use rusqlite::{params, OptionalExtension};
use std::{collections::BTreeMap, net::TcpListener, sync::Mutex, thread};

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
    /// Immutable cumulative retained ciphertext budget for this key identity.
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
}
impl Default for ServiceLimits {
    fn default() -> Self {
        Self {
            max_connections: 16,
            request_timeout: Duration::from_secs(10),
            window: Duration::from_secs(1),
            requests_per_window: 128,
            bytes_per_window: 64 * 1024 * 1024,
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
}
/// An explicitly enrolled, single-namespace durable mailbox service. Item
/// publication and its per-key storage charge commit in one SQLite transaction
/// behind a single post-commit durability barrier. Socket reads/writes never
/// hold the mailbox mutex. Finite credential work and in-flight caps prevent
/// one authenticated key from using every service slot. Pre-authentication
/// work is bounded three ways: worker count, handshakes per window, and a
/// handshake-phase deadline tighter than the whole request; over-limit
/// sockets get a bounded fatal alert instead of a silent drop.
pub struct Service {
    state: Arc<Mutex<State>>,
    config: Arc<ServerConfig>,
}

impl Service {
    /// Explicitly enroll an EMPTY mailbox for TLS admission. Existing or used
    /// enrollments refuse. Never infer the owner of legacy retained ciphertext.
    pub fn initialize(store: FileStore) -> Result<()> {
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
        let format: i64 = store
            .conn
            .query_row("SELECT format FROM tls_meta WHERE id=1", [], |r| r.get(0))
            .map_err(|_| NetError::Unavailable)?;
        if format != 1 {
            return Err(NetError::Bounds);
        }
        // Per-key quota scans must not grow with every retained item. Stores
        // enrolled before this index existed are repaired once, idempotently.
        store
            .conn
            .execute_batch("CREATE INDEX IF NOT EXISTS tls_charges_by_key ON tls_charges(key_id)")
            .map_err(|_| NetError::Unavailable)?;
        // A local compatibility writer cannot silently add uncharged items.
        let bad: i64 = store.conn.query_row("SELECT (SELECT COUNT(*) FROM items LEFT JOIN tls_charges ON items.digest=tls_charges.digest WHERE tls_charges.digest IS NULL OR tls_charges.bytes != length(items.payload)) + (SELECT COUNT(*) FROM tls_charges LEFT JOIN items ON items.digest=tls_charges.digest WHERE items.digest IS NULL) + (SELECT COUNT(*) FROM tls_keys WHERE length(id)!=16 OR id=zeroblob(16) OR max_items<1 OR max_bytes<1) + (SELECT COUNT(*) FROM tls_charges LEFT JOIN tls_keys ON tls_charges.key_id=tls_keys.id WHERE tls_keys.id IS NULL OR tls_charges.bytes<1)", [], |r| r.get(0)).map_err(|_| NetError::Unavailable)?;
        let count: i64 = store
            .conn
            .query_row("SELECT COUNT(*) FROM tls_keys", [], |r| r.get(0))
            .map_err(|_| NetError::Unavailable)?;
        if bad != 0 || !(0..=64).contains(&count) {
            return Err(NetError::Unavailable);
        }
        let over: i64 = store.conn.query_row("SELECT COUNT(*) FROM tls_keys k WHERE (SELECT COUNT(*) FROM tls_charges c WHERE c.key_id=k.id)>k.max_items OR (SELECT COALESCE(SUM(bytes),0) FROM tls_charges c WHERE c.key_id=k.id)>k.max_bytes", [], |r| r.get(0)).map_err(|_| NetError::Unavailable)?;
        if over != 0 {
            return Err(NetError::Unavailable);
        }
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
            state: Arc::new(Mutex::new(State {
                store,
                credentials,
                limits,
                window_start: Instant::now(),
                global: Work::default(),
                keys: BTreeMap::new(),
                poisoned: false,
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
        let mut workers: Vec<thread::JoinHandle<()>> = Vec::new();
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
                if workers[index].is_finished() {
                    if workers.swap_remove(index).join().is_err() {
                        failure = Some(NetError::Unavailable);
                    }
                } else {
                    index += 1;
                }
            }
            if failure.is_some() {
                break;
            }
            let (stream, _) = match listener.accept() {
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
            }
            if workers.len() >= max || handshakes >= max_handshakes {
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
            let deadline = Instant::now() + timeout;
            let supervisor = thread::current();
            match thread::Builder::new()
                .name("vhalla-relay-tls".into())
                .spawn(move || {
                    let _ = serve_one(stream, config, state, deadline);
                    supervisor.unpark();
                }) {
                Ok(worker) => workers.push(worker),
                Err(_) => {
                    failure = Some(NetError::Unavailable);
                    break;
                }
            }
        }
        // Close the listening endpoint before draining existing deadline-bound
        // sockets. A poisoned service cannot keep admitting a false healthy route.
        drop(listener);
        for worker in workers {
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
    let response = if request[0] == OP_PUT {
        put(&mut s, id, &request[33..])
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
    let result = write_frame(&mut tls, code, &body, deadline);
    drop(admitted);
    result
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
            let (count,bytes,max_count,max_bytes): (i64,i64,i64,i64) = store.conn.query_row("SELECT (SELECT COUNT(*) FROM tls_charges WHERE key_id=?1),(SELECT COALESCE(SUM(bytes),0) FROM tls_charges WHERE key_id=?1),max_items,max_bytes FROM tls_keys WHERE id=?1", params![id.as_slice()], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).map_err(|_| super::super::Error::Storage)?;
            let size =
                i64::try_from(item.payload().len()).map_err(|_| super::super::Error::Bounds)?;
            if count >= max_count || bytes.checked_add(size).is_none_or(|n| n > max_bytes) {
                return Err(super::super::Error::Capacity);
            }
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
