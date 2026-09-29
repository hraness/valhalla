//! Public-key authenticated QUIC for opaque private-room mailboxes.
//!
//! Endpoint keys authenticate hosts; independent bearer credentials retain the
//! existing mailbox permissions and durable quotas. Routing hints grant no room
//! authority. No public address-lookup service is configured. Synchronous clients
//! own a separate runtime, including when called from an existing async runtime.
use super::{
    codec::*,
    delivery,
    net::{NetError, PageSource, RelayToken, ScanFailure},
    tls::{service::RequestHandler, Service},
    RelayItem, RelayNamespace, RelayPage, RelayReceipt,
};
use ::iroh::{
    endpoint::{presets, QuicTransportConfig},
    Endpoint, EndpointAddr, RelayMap, RelayMode, RelayUrl, SecretKey,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc as sync_mpsc, Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinSet,
};
type Result<T> = std::result::Result<T, NetError>;
const MAX_EXCHANGE: Duration = Duration::from_secs(25);
const STARTUP_TIMEOUT: Duration = Duration::from_secs(20);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(4);
const MAX_CLIENT_WORKERS: usize = 32;
/// Number 0's production North America east relay in iroh 1.2.0.
pub const DEFAULT_RELAY_URL: &str = "https://use1-1.relay.n0.iroh.link.";
/// Public host identity and bounded routing hints; contains no admission secret.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IrohEndpoint {
    /// Canonical hexadecimal Ed25519 endpoint public key.
    pub endpoint_id: String,
    /// Explicit HTTPS relay assisting NAT traversal, or direct-only transport.
    pub relay_url: Option<String>,
    /// Optional numeric direct UDP addresses; never wildcard addresses.
    pub addresses: Vec<SocketAddr>,
}
pub(crate) fn checked_relay(value: &str) -> Result<RelayUrl> {
    if value.len() > 2048 {
        return Err(NetError::Bounds);
    }
    let url: RelayUrl = value.parse().map_err(|_| NetError::Bounds)?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        return Err(NetError::Bounds);
    }
    Ok(url)
}
fn valid_ip(address: SocketAddr) -> bool {
    match address {
        SocketAddr::V4(a) => {
            !a.ip().is_unspecified()
                && !a.ip().is_multicast()
                && !a.ip().is_broadcast()
                && !a.ip().is_link_local()
        }
        SocketAddr::V6(a) => {
            !a.ip().is_unspecified()
                && !a.ip().is_multicast()
                && !a.ip().is_unicast_link_local()
                && a.ip().to_ipv4_mapped().is_none()
                && a.scope_id() == 0
                && a.flowinfo() == 0
        }
    }
}
impl IrohEndpoint {
    /// Validate without starting a runtime or making any network request.
    pub fn validate(&self) -> Result<()> {
        self.address().map(|_| ())
    }
    fn address(&self) -> Result<EndpointAddr> {
        if self.endpoint_id.len() != 64 {
            return Err(NetError::Bounds);
        }
        let id: ::iroh::EndpointId = self.endpoint_id.parse().map_err(|_| NetError::Bounds)?;
        let unique: std::collections::BTreeSet<_> = self.addresses.iter().collect();
        if unique.len() != self.addresses.len()
            || id.to_string() != self.endpoint_id
            || self.addresses.len() > 16
            || (self.addresses.is_empty() && self.relay_url.is_none())
            || self
                .addresses
                .iter()
                .any(|a| a.port() == 0 || !valid_ip(*a))
        {
            return Err(NetError::Bounds);
        }
        let mut addr = EndpointAddr::new(id);
        if let Some(relay) = &self.relay_url {
            addr = addr.with_relay_url(checked_relay(relay)?);
        }
        for address in &self.addresses {
            addr = addr.with_ip_addr(*address);
        }
        Ok(addr)
    }
    /// Stable trust commitment. Moving a host or rotating relay hints does not
    /// redirect retained jobs because its authenticated public key stays pinned.
    pub fn delivery_endpoint_id(&self, namespace: RelayNamespace) -> Result<delivery::EndpointId> {
        let addr = self.address()?;
        let mut hash = Sha256::new();
        hash.update(b"vhalla/private/delivery-endpoint/iroh/v1");
        hash.update(addr.id.as_bytes());
        hash.update(namespace.as_bytes());
        delivery::EndpointId::from_bytes(hash.finalize().into()).map_err(|_| NetError::Bounds)
    }
}
/// Derive public host identity from a separately stored random secret seed.
pub fn endpoint_id_from_secret(secret: &[u8; 32]) -> String {
    SecretKey::from_bytes(secret).public().to_string()
}
fn protocol(namespace: RelayNamespace) -> Vec<u8> {
    let mut protocol = b"vhalla-relay/iroh/1/".to_vec();
    protocol.extend_from_slice(namespace.as_bytes());
    protocol
}
fn runtime() -> Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .max_blocking_threads(64)
        .enable_all()
        .build()
        .map_err(|_| NetError::Unavailable)
}
fn builder(relay: Option<&str>) -> Result<::iroh::endpoint::Builder> {
    let transport = QuicTransportConfig::builder()
        .max_concurrent_bidi_streams(1u32.into())
        .max_concurrent_uni_streams(0u32.into())
        .stream_receive_window((256u32 * 1024).into())
        .receive_window((1024u32 * 1024).into())
        .send_window(1024 * 1024)
        .datagram_receive_buffer_size(None)
        .datagram_send_buffer_size(0)
        .build();
    let mut builder = Endpoint::builder(presets::Minimal).transport_config(transport);
    if let Some(relay) = relay {
        builder = builder.relay_mode(RelayMode::Custom(RelayMap::from_iter([checked_relay(
            relay,
        )?])));
    }
    Ok(builder)
}
struct Exchange {
    op: u8,
    body: Vec<u8>,
    deadline: Instant,
    reply: sync_mpsc::SyncSender<Result<Vec<u8>>>,
}
struct ClientWorker {
    sender: Option<mpsc::Sender<Exchange>>,
    join: Option<thread::JoinHandle<()>>,
}
impl Drop for ClientWorker {
    fn drop(&mut self) {
        self.sender.take();
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}
impl ClientWorker {
    fn start(
        addr: EndpointAddr,
        relay_url: Option<&str>,
        token: RelayToken,
        namespace: RelayNamespace,
        deadline: Instant,
    ) -> Result<Self> {
        let deadline = deadline.min(Instant::now() + STARTUP_TIMEOUT);
        let configured = builder(relay_url)?;
        let (sender, mut receiver) = mpsc::channel::<Exchange>(MAX_CLIENT_WORKERS);
        let (ready_tx, ready_rx) = sync_mpsc::sync_channel(1);
        let worker_token = token;
        let join = thread::Builder::new().name("vhalla-iroh-client".into()).spawn(move || {
            let Ok(runtime) = runtime() else { let _ = ready_tx.send(Err(NetError::Unavailable)); return; };
            runtime.block_on(async move {
                let endpoint = match tokio::time::timeout_at(deadline.into(), configured.bind()).await { Ok(Ok(ep)) => ep, _ => { let _ = ready_tx.send(Err(NetError::Connect)); return; } };
                if ready_tx.send(Ok(())).is_err() { endpoint.close().await; return; }
                let mut tasks = JoinSet::new();
                loop {
                    tokio::select! {
                        command = receiver.recv() => {
                            let Some(command) = command else { break; };
                            if tasks.len() >= MAX_CLIENT_WORKERS { let _ = command.reply.send(Err(NetError::Capacity)); continue; }
                            let (endpoint, addr, token) = (endpoint.clone(), addr.clone(), worker_token);
                            tasks.spawn(async move {
                                let outcome = exchange(&endpoint, addr, &token, namespace, command.op, &command.body, command.deadline).await;
                                let _ = command.reply.send(outcome);
                            });
                        }
                        _ = tasks.join_next(), if !tasks.is_empty() => {}
                    }
                }
                tasks.abort_all();
                while tasks.join_next().await.is_some() {}
                endpoint.close().await;
            });
        }).map_err(|_| NetError::Unavailable)?;
        match ready_rx.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(Ok(())) => Ok(ClientWorker {
                sender: Some(sender),
                join: Some(join),
            }),
            result => {
                drop(sender);
                let _ = join.join();
                Err(result
                    .ok()
                    .and_then(|r| r.err())
                    .unwrap_or(NetError::Timeout))
            }
        }
    }
}
/// Cloneable synchronous client, with one shared owned runtime and endpoint.
#[derive(Clone)]
pub struct IrohRelay {
    worker: Arc<Mutex<Option<Arc<ClientWorker>>>>,
    address: EndpointAddr,
    relay_url: Option<String>,
    token: RelayToken,
    namespace: RelayNamespace,
    identity: delivery::EndpointId,
}
impl IrohRelay {
    /// Pin the endpoint key and namespace without starting a runtime or network
    /// activity. The first exchange starts the shared worker lazily.
    pub fn new(
        endpoint: IrohEndpoint,
        token: RelayToken,
        namespace: RelayNamespace,
    ) -> Result<Self> {
        let address = endpoint.address()?;
        let identity = endpoint.delivery_endpoint_id(namespace)?;
        Ok(Self {
            worker: Arc::new(Mutex::new(None)),
            address,
            relay_url: endpoint.relay_url,
            token,
            namespace,
            identity,
        })
    }
    fn exchange(&self, op: u8, body: &[u8], deadline: Instant) -> Result<Vec<u8>> {
        if Instant::now() >= deadline {
            return Err(NetError::Timeout);
        }
        let worker = loop {
            match self.worker.try_lock() {
                Ok(mut selected) => {
                    if selected.is_none() {
                        *selected = Some(Arc::new(ClientWorker::start(
                            self.address.clone(),
                            self.relay_url.as_deref(),
                            self.token,
                            self.namespace,
                            deadline,
                        )?));
                    }
                    break selected.as_ref().expect("initialized").clone();
                }
                Err(std::sync::TryLockError::Poisoned(_)) => return Err(NetError::Unavailable),
                Err(std::sync::TryLockError::WouldBlock) => {
                    if Instant::now() >= deadline {
                        return Err(NetError::Timeout);
                    }
                    thread::sleep(Duration::from_millis(1));
                }
            }
        };
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or(NetError::Timeout)?;
        let (reply, receiver) = sync_mpsc::sync_channel(1);
        worker
            .sender
            .as_ref()
            .ok_or(NetError::Unavailable)?
            .try_send(Exchange {
                op,
                body: body.to_vec(),
                deadline,
                reply,
            })
            .map_err(|error| {
                if matches!(error, mpsc::error::TrySendError::Full(_)) {
                    NetError::Capacity
                } else {
                    NetError::Unavailable
                }
            })?;
        receiver.recv_timeout(remaining).map_err(|error| {
            if matches!(error, sync_mpsc::RecvTimeoutError::Timeout) {
                NetError::Timeout
            } else {
                NetError::Unavailable
            }
        })?
    }
    /// Selected mailbox namespace.
    pub fn namespace(&self) -> RelayNamespace {
        self.namespace
    }
    /// Authenticated transport trust commitment.
    pub fn endpoint_id(&self) -> delivery::EndpointId {
        self.identity
    }
    pub(super) fn token_matches(&self, candidate: &[u8; 32]) -> bool {
        self.token
            .as_bytes()
            .iter()
            .zip(candidate)
            .fold(0u8, |v, (a, b)| v | (a ^ b))
            == 0
    }
    /// Submit immutable encrypted bytes under the default deadline.
    pub fn submit(&self, item: &RelayItem) -> Result<RelayReceipt> {
        self.submit_until(item, Instant::now() + MAX_EXCHANGE)
    }
    /// Submit within an absolute deadline. A timeout after sending is uncertain.
    pub fn submit_until(&self, item: &RelayItem, deadline: Instant) -> Result<RelayReceipt> {
        if item.namespace() != self.namespace {
            return Err(NetError::Scope);
        }
        let encoded = item.encode().map_err(|_| NetError::Bounds)?;
        decode_receipt(
            &self.exchange(
                OP_PUT,
                &encoded,
                deadline.min(Instant::now() + MAX_EXCHANGE),
            )?,
            item,
        )
    }
    /// Read one bounded canonical page.
    pub fn page(&self, after: u64, limit: usize) -> Result<RelayPage> {
        self.page_until(after, limit, Instant::now() + MAX_EXCHANGE)
    }
    /// Read within an absolute deadline.
    pub fn page_until(&self, after: u64, limit: usize, deadline: Instant) -> Result<RelayPage> {
        self.read_page(
            after,
            limit,
            page_request(after, limit)?,
            deadline.min(Instant::now() + MAX_EXCHANGE),
        )
    }
    /// Hold a page request open for at most the requested wait.
    pub fn page_wait_until(
        &self,
        after: u64,
        limit: usize,
        wait: Duration,
        deadline: Instant,
    ) -> Result<RelayPage> {
        self.read_page(
            after,
            limit,
            page_wait_request(after, limit, wait)?,
            deadline.min(Instant::now() + wait + MAX_EXCHANGE),
        )
    }
    fn read_page(
        &self,
        after: u64,
        limit: usize,
        request: Vec<u8>,
        deadline: Instant,
    ) -> Result<RelayPage> {
        let page = decode_page(&self.exchange(OP_PAGE, &request, deadline)?, after, limit)?;
        if page
            .records
            .iter()
            .any(|r| r.item.namespace() != self.namespace)
        {
            return Err(NetError::Scope);
        }
        Ok(page)
    }
}
impl PageSource for IrohRelay {
    fn source_page(
        &self,
        after: u64,
        limit: usize,
        deadline: Instant,
    ) -> std::result::Result<RelayPage, ScanFailure> {
        self.page_until(after, limit, deadline)
            .map_err(ScanFailure::Net)
    }
}
impl delivery::Transport for IrohRelay {
    fn endpoint_id(&self) -> delivery::EndpointId {
        self.identity
    }
    fn namespace(&self) -> RelayNamespace {
        self.namespace
    }
    fn submit_until(&mut self, item: &RelayItem, deadline: Instant) -> Result<RelayReceipt> {
        IrohRelay::submit_until(self, item, deadline)
    }
}
async fn exchange(
    endpoint: &Endpoint,
    addr: EndpointAddr,
    token: &RelayToken,
    namespace: RelayNamespace,
    op: u8,
    body: &[u8],
    deadline: Instant,
) -> Result<Vec<u8>> {
    if Instant::now() >= deadline {
        return Err(NetError::Timeout);
    }
    let connection = tokio::time::timeout_at(
        (deadline.min(Instant::now() + HANDSHAKE_TIMEOUT)).into(),
        endpoint.connect(addr, &protocol(namespace)),
    )
    .await
    .map_err(|_| NetError::Connect)?
    .map_err(|_| NetError::Connect)?;
    let result = tokio::time::timeout_at(deadline.into(), async {
        let (mut send, mut recv) = connection.open_bi().await.map_err(|_| NetError::Connect)?;
        // The token is materialized only after the pinned host handshake succeeds.
        let mut body_with_token = token.as_bytes().to_vec();
        body_with_token.extend_from_slice(body);
        send.write_all(&frame(op, &body_with_token))
            .await
            .map_err(|_| NetError::Unavailable)?;
        send.finish().map_err(|_| NetError::Unavailable)?;
        let raw = recv
            .read_to_end(MAX_RESPONSE + 4)
            .await
            .map_err(|_| NetError::Malformed)?;
        let (status, body) = decode_frame(&raw, MAX_RESPONSE)?;
        decode_status(status, body)
    })
    .await
    .map_err(|_| NetError::Timeout)
    .and_then(|result| result);
    connection.close(0u32.into(), b"done");
    result
}
struct ServerJob {
    service: Service,
    limit: Option<u64>,
    stop: Arc<AtomicBool>,
    #[cfg(feature = "habitat-link")]
    habitat_link: Option<crate::habitat_link::HabitatLinkService>,
}
/// A bound endpoint with an owned runtime; dropping it closes and joins the worker.
pub struct IrohListener {
    endpoint: IrohEndpoint,
    handle: Endpoint,
    sender: Option<oneshot::Sender<ServerJob>>,
    join: Option<thread::JoinHandle<Result<()>>>,
}
impl IrohListener {
    /// Bind a stable host key. Relay mode waits at most twenty seconds for its
    /// configured relay; direct-only mode makes no outbound discovery request.
    pub fn bind(secret_key: [u8; 32], bind: SocketAddr, relay_url: Option<&str>) -> Result<Self> {
        if secret_key == [0; 32] {
            return Err(NetError::Bounds);
        }
        let configured = builder(relay_url)?
            .secret_key(SecretKey::from_bytes(&secret_key))
            .clear_ip_transports()
            .bind_addr(bind)
            .map_err(|_| NetError::Bounds)?;
        let relay_url = relay_url.map(str::to_owned);
        let (sender, receiver) = oneshot::channel::<ServerJob>();
        let (ready_tx, ready_rx) = sync_mpsc::sync_channel(1);
        let join = thread::Builder::new()
            .name("vhalla-iroh-host".into())
            .spawn(move || {
                let runtime = runtime()?;
                runtime.block_on(async move {
                    let endpoint =
                        match tokio::time::timeout(STARTUP_TIMEOUT, configured.bind()).await {
                            Ok(Ok(ep)) => ep,
                            _ => {
                                let _ = ready_tx.send(Err(NetError::Connect));
                                return Err(NetError::Connect);
                            }
                        };
                    if relay_url.is_some()
                        && tokio::time::timeout(STARTUP_TIMEOUT, endpoint.online())
                            .await
                            .is_err()
                    {
                        let _ = ready_tx.send(Err(NetError::Connect));
                        endpoint.close().await;
                        return Err(NetError::Connect);
                    }
                    let published = IrohEndpoint {
                        endpoint_id: endpoint.id().to_string(),
                        relay_url,
                        addresses: endpoint
                            .addr()
                            .ip_addrs()
                            .copied()
                            .filter(|a| valid_ip(*a) && a.port() != 0)
                            .take(16)
                            .collect(),
                    };
                    if ready_tx
                        .send(published.validate().map(|_| (published, endpoint.clone())))
                        .is_err()
                    {
                        endpoint.close().await;
                        return Ok(());
                    }
                    let result = match receiver.await {
                        Ok(job) => serve(&endpoint, job).await,
                        Err(_) => Ok(()),
                    };
                    endpoint.close().await;
                    result
                })
            })
            .map_err(|_| NetError::Unavailable)?;
        match ready_rx.recv_timeout(STARTUP_TIMEOUT * 2 + Duration::from_secs(2)) {
            Ok(Ok((endpoint, handle))) => Ok(Self {
                endpoint,
                handle,
                sender: Some(sender),
                join: Some(join),
            }),
            result => {
                drop(sender);
                let _ = join.join();
                Err(result
                    .ok()
                    .and_then(|r| r.err())
                    .unwrap_or(NetError::Timeout))
            }
        }
    }
    /// Configure the namespace before announcing readiness; incoming handshakes
    /// can then queue while the service's supervisor is being started.
    pub fn set_namespace(&self, namespace: RelayNamespace) {
        self.handle.set_alpns(vec![protocol(namespace)]);
    }
    /// Current bound identity and initial connection hints.
    pub fn endpoint(&self) -> IrohEndpoint {
        self.endpoint.clone()
    }
}
impl Drop for IrohListener {
    fn drop(&mut self) {
        self.sender.take();
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}
impl Service {
    /// Serve the existing mailbox with bounded QUIC connections. Stops admission
    /// promptly, wakes waiting pages and joins all workers before releasing it.
    pub fn serve_iroh_until(
        self,
        listener: IrohListener,
        limit: Option<u64>,
        stop: Arc<AtomicBool>,
    ) -> Result<()> {
        serve_iroh_job(
            listener,
            ServerJob {
                service: self,
                limit,
                stop,
                #[cfg(feature = "habitat-link")]
                habitat_link: None,
            },
        )
    }
    /// Serve the mailbox and, on the same endpoint, an explicitly enabled
    /// Habitat Link service. Only this entry point adds the Habitat Link ALPN;
    /// connections negotiating it are handed to the service after the
    /// listener's handshake, source, and per-peer connection budgets, and the
    /// mailbox's own request handler never sees them. Such a connection holds
    /// one of the listener's connection slots for the service's idle bound
    /// rather than the mailbox request timeout; the listener's transport
    /// config still caps it at one peer-opened stream at a time.
    #[cfg(feature = "habitat-link")]
    pub fn serve_iroh_with_habitat_link_until(
        self,
        listener: IrohListener,
        limit: Option<u64>,
        stop: Arc<AtomicBool>,
        habitat_link: crate::habitat_link::HabitatLinkService,
    ) -> Result<()> {
        serve_iroh_job(
            listener,
            ServerJob {
                service: self,
                limit,
                stop,
                habitat_link: Some(habitat_link),
            },
        )
    }
}
fn serve_iroh_job(mut listener: IrohListener, job: ServerJob) -> Result<()> {
    listener
        .sender
        .take()
        .ok_or(NetError::Unavailable)?
        .send(job)
        .map_err(|_| NetError::Unavailable)?;
    listener
        .join
        .take()
        .ok_or(NetError::Unavailable)?
        .join()
        .map_err(|_| NetError::Unavailable)?
}
/// Direct peers share the same IP(/64) budget as TCP. Relayed peers are
/// keyed by their authenticated relay identity; neither grants mailbox access.
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
enum Source {
    Ip(std::net::IpAddr),
    Relay(::iroh::EndpointId),
}
#[derive(Default)]
struct Sources {
    live: BTreeMap<Source, usize>,
    attempts: BTreeMap<Source, u32>,
}
impl Sources {
    fn admit(&mut self, source: Source, max: usize, attempts: u32) -> bool {
        if self.live.get(&source).copied().unwrap_or(0) >= (max / 4).max(1)
            || self.attempts.get(&source).copied().unwrap_or(0) >= (attempts / 4).max(1)
            || (!self.attempts.contains_key(&source) && self.attempts.len() >= 4096)
        {
            return false;
        }
        *self.live.entry(source).or_default() += 1;
        *self.attempts.entry(source).or_default() += 1;
        true
    }
}
struct SourceGuard {
    sources: Arc<Mutex<Sources>>,
    source: Option<Source>,
}
impl Drop for SourceGuard {
    fn drop(&mut self) {
        if let (Some(source), Ok(mut sources)) = (self.source, self.sources.lock()) {
            if let Some(count) = sources.live.get_mut(&source) {
                *count -= 1;
                if *count == 0 {
                    sources.live.remove(&source);
                }
            }
        }
    }
}
struct PeerGuard {
    peers: Arc<Mutex<BTreeMap<::iroh::EndpointId, usize>>>,
    id: ::iroh::EndpointId,
}
impl Drop for PeerGuard {
    fn drop(&mut self) {
        if let Ok(mut peers) = self.peers.lock() {
            if let Some(count) = peers.get_mut(&self.id) {
                *count -= 1;
                if *count == 0 {
                    peers.remove(&self.id);
                }
            }
        }
    }
}
async fn serve(endpoint: &Endpoint, job: ServerJob) -> Result<()> {
    let (namespace, limits) = job.service.iroh_parameters()?;
    #[cfg(feature = "habitat-link")]
    endpoint.set_alpns(crate::habitat_link::with_habitat_link_alpn(
        vec![protocol(namespace)],
        job.habitat_link.is_some(),
    ));
    #[cfg(not(feature = "habitat-link"))]
    endpoint.set_alpns(vec![protocol(namespace)]);
    let draining = Arc::new(AtomicBool::new(false));
    let peers = Arc::new(Mutex::new(BTreeMap::new()));
    let sources = Arc::new(Mutex::new(Sources::default()));
    let mut tasks = JoinSet::new();
    let mut accepted = 0;
    let mut handshakes = 0u32;
    let mut start = Instant::now();
    let mut failed = false;
    while !job.stop.load(Ordering::Acquire) && job.limit.is_none_or(|limit| accepted < limit) {
        if job.service.unhealthy() {
            failed = true;
            break;
        }
        while let Some(result) = tasks.try_join_next() {
            if result.is_err() {
                failed = true;
            }
        }
        if failed {
            break;
        }
        let incoming = tokio::select! { incoming=endpoint.accept()=>match incoming{Some(v)=>v,None=>break}, _=tokio::time::sleep(Duration::from_millis(20))=>continue };
        accepted += 1;
        if start.elapsed() >= limits.window {
            start = Instant::now();
            handshakes = 0;
            sources
                .lock()
                .map_err(|_| NetError::Unavailable)?
                .attempts
                .clear();
        }
        if tasks.len() >= limits.max_connections
            || handshakes >= limits.requests_per_window.saturating_mul(2)
        {
            incoming.refuse();
            continue;
        }
        let source = match incoming.remote_addr() {
            ::iroh::endpoint::IncomingAddr::Ip(addr) => {
                super::tls::service::remote_source(addr.ip()).map(Source::Ip)
            }
            ::iroh::endpoint::IncomingAddr::Relay { endpoint_id, .. } => {
                Some(Source::Relay(endpoint_id))
            }
            _ => {
                incoming.refuse();
                continue;
            }
        };
        if source.is_some_and(|source| {
            !sources.lock().is_ok_and(|mut counts| {
                counts.admit(
                    source,
                    limits.max_connections,
                    limits.requests_per_window.saturating_mul(2),
                )
            })
        }) {
            incoming.refuse();
            continue;
        }
        let source_guard = SourceGuard {
            sources: sources.clone(),
            source,
        };
        handshakes += 1;
        let handler = job.service.request_handler();
        let draining = draining.clone();
        let peers = peers.clone();
        #[cfg(feature = "habitat-link")]
        let habitat_link = job.habitat_link.clone();
        tasks.spawn(async move {
            let _source_guard = source_guard;
            serve_one(
                incoming,
                handler,
                draining,
                peers,
                limits.max_connections,
                Instant::now() + limits.request_timeout,
                #[cfg(feature = "habitat-link")]
                habitat_link,
            )
            .await
        });
    }
    endpoint.set_alpns(Vec::new());
    draining.store(true, Ordering::Release);
    job.service.wake_waiters();
    while let Some(result) = tasks.join_next().await {
        if result.is_err() {
            failed = true;
        }
    }
    if failed || job.service.unhealthy() {
        Err(NetError::Unavailable)
    } else {
        Ok(())
    }
}
async fn serve_one(
    incoming: ::iroh::endpoint::Incoming,
    handler: RequestHandler,
    draining: Arc<AtomicBool>,
    peers: Arc<Mutex<BTreeMap<::iroh::EndpointId, usize>>>,
    max: usize,
    deadline: Instant,
    #[cfg(feature = "habitat-link")] habitat_link: Option<crate::habitat_link::HabitatLinkService>,
) -> Result<()> {
    let connection = tokio::time::timeout_at(
        deadline.min(Instant::now() + HANDSHAKE_TIMEOUT).into(),
        incoming,
    )
    .await
    .map_err(|_| NetError::Timeout)?
    .map_err(|_| NetError::Connect)?;
    let guard = {
        let id = connection.remote_id();
        let mut counts = peers.lock().map_err(|_| NetError::Unavailable)?;
        let count = counts.entry(id).or_default();
        if *count >= (max / 4).max(1) {
            connection.close(1u32.into(), b"capacity");
            return Err(NetError::Capacity);
        }
        *count += 1;
        PeerGuard {
            peers: peers.clone(),
            id,
        }
    };
    #[cfg(feature = "habitat-link")]
    if let Some(service) =
        habitat_link.filter(|_| connection.alpn() == crate::habitat_link::HABITAT_LINK_ALPN)
    {
        // Habitat Link owns its stream, read and reply bounds; the mailbox
        // request handler is never consulted for this connection.
        let result = service.serve_connection(connection).await;
        drop(guard);
        return result.map(|_| ()).map_err(|_| NetError::Malformed);
    }
    let result = async {
        let (mut send, mut recv) = tokio::time::timeout_at(deadline.into(), connection.accept_bi())
            .await
            .map_err(|_| NetError::Timeout)?
            .map_err(|_| NetError::Malformed)?;
        let raw = tokio::time::timeout_at(deadline.into(), recv.read_to_end(MAX_REQUEST + 4))
            .await
            .map_err(|_| NetError::Timeout)?
            .map_err(|_| NetError::Malformed)?;
        decode_frame(&raw, MAX_REQUEST)?;
        // SQLite synchronization and held-page condvars run on bounded blocking workers.
        let cancelled = Arc::new(AtomicBool::new(false));
        let processing_handler = handler.clone();
        let processing_cancelled = cancelled.clone();
        let mut processing = tokio::task::spawn_blocking(move || {
            processing_handler.process(&raw[4..], deadline, draining, &processing_cancelled)
        });
        let outcome = tokio::select! {
            outcome = &mut processing => outcome,
            _ = async {
                tokio::select! {
                    _ = connection.closed() => {}
                    _ = send.stopped() => {}
                }
            } => {
                // A disconnected or cancelled PAGE no longer needs its wait. Keep the
                // blocking operation joined: cancellation never abandons a PUT
                // or releases its admission guard before storage completes.
                loop {
                    if handler.cancel_wait(&cancelled) {
                        break processing.await;
                    }
                    tokio::select! {
                        outcome = &mut processing => break outcome,
                        _ = tokio::time::sleep(Duration::from_millis(1)) => {}
                    }
                }
            }
        };
        let reply = match outcome {
            Ok(reply) => reply?,
            Err(error) if error.is_panic() => std::panic::resume_unwind(error.into_panic()),
            Err(_) => return Err(NetError::Unavailable),
        };
        let bytes = frame(reply.code, &reply.body);
        tokio::time::timeout_at(reply.deadline.into(), async {
            send.write_all(&bytes)
                .await
                .map_err(|_| NetError::Unavailable)?;
            send.finish().map_err(|_| NetError::Unavailable)?;
            send.stopped().await.map_err(|_| NetError::Unavailable)?;
            Ok(())
        })
        .await
        .map_err(|_| NetError::Timeout)?
    }
    .await;
    connection.close(0u32.into(), b"done");
    drop(guard);
    result
}
#[cfg(test)]
mod tests;
