use bytes::Bytes;
use http_body_util::Full;
use hyper::{
    body::Incoming, header, server::conn::http1, service::service_fn, HeaderMap, Method, Request,
    Response, StatusCode,
};
use hyper_util::rt::{TokioIo, TokioTimer};
use std::{
    collections::BTreeMap,
    convert::Infallible,
    fs::{File, OpenOptions},
    future::Future,
    io::{self, Read},
    net::{IpAddr, SocketAddr},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{net::TcpListener, task::JoinSet, time::timeout};
use vhalla_identity::Identity;
use vhalla_journal::{FsStore, Journal, PublishedRange, PublishedReadError};
use vhalla_public_client::{Bootstrap, CertifiedClient, MAX_BOOTSTRAP_BYTES};
use vhalla_public_protocol::{
    response::{hex, BundlePage, ReadKind, ReadRequest, UnsignedResponse, PROOF_HEADER},
    Capabilities, Endpoint, PeerAdvertisement, Scheme, SequenceAnchor, VerificationPolicy,
    MAX_ADVERTISEMENT_BYTES, MAX_CLOCK_SKEW_SECONDS, MAX_TTL_SECONDS,
};

mod activity;
mod continuity;
pub use continuity::{ContinuityConfig, ContinuityRoomConfig};
mod discovery;
pub use activity::{
    ActivityConfig, ActivityRoomConfig, ACTIVITY_REPLAY_BUDGET, MAX_ACTIVITY_ROOMS,
};
pub use discovery::{DiscoveryConfig, MAX_DISCOVERY_PEERS};

mod renewal;
pub use renewal::{ManagedBoundPeer, ManagedPeer, ADVERTISEMENT_LIFETIME_SECONDS};

/// Default HTTP bind; public TLS termination must be explicitly operated.
pub const DEFAULT_LISTEN: &str = "127.0.0.1:9790";
/// Bound on admitted sockets AND unfinished blocking read jobs.
pub const MAX_CONNECTIONS: usize = 64;
/// Bound per immediate socket source IP (a proxy counts as its own one IP).
pub const MAX_CONNECTIONS_PER_IP: usize = 8;
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(15);
const READ_TIMEOUT: Duration = Duration::from_secs(10);
const HEADER_TIMEOUT: Duration = Duration::from_secs(5);
const HEADER_BYTES: usize = 8192;
const MAX_HEADERS: usize = 32;

/// Explicit single browser origin, with no credentials or wildcard policy.
#[derive(Clone, Debug)]
pub struct CorsOrigin(String);
impl CorsOrigin {
    /// Accept an exact HTTPS origin. Its host uses the public endpoint policy;
    /// default port 443 may be omitted, as in a browser's serialized Origin.
    pub fn https(raw: &str) -> Result<Self, Error> {
        let authority = raw.strip_prefix("https://").ok_or(Error::Config)?;
        if authority.contains('/') || authority.is_empty() {
            return Err(Error::Config);
        }
        let explicit_port = if authority.starts_with('[') {
            authority.contains("]:")
        } else {
            authority.contains(':')
        };
        let endpoint = if explicit_port {
            format!("{raw}/vhalla/v1")
        } else {
            format!("{raw}:443/vhalla/v1")
        };
        Endpoint::parse(&endpoint).map_err(|_| Error::Config)?;
        Ok(Self(raw.to_owned()))
    }
    /// Explicit development-only loopback HTTP origin. Never inferred from
    /// request headers, listener settings or an arbitrary hostname.
    pub fn loopback_development(address: SocketAddr) -> Result<Self, Error> {
        if !address.ip().is_loopback() || address.port() == 0 {
            return Err(Error::Config);
        }
        Ok(Self(format!("http://{address}")))
    }
    /// Exact permitted serialized browser Origin value.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Operator-supplied immutable configuration. Opening never generates keys or
/// bootstrap pins, renews advertisements, repairs journals or starts listeners.
#[derive(Clone, Debug)]
pub struct Config {
    /// Independently pinned canonical bootstrap file.
    pub bootstrap_file: PathBuf,
    /// Full SHA-256 configuration pin obtained independently of this server.
    pub bootstrap_pin: [u8; 32],
    /// Existing native custody directory; lifetime exclusive lock is retained.
    pub identity_dir: PathBuf,
    /// Existing application journal directory, read without recovery.
    pub journal_dir: PathBuf,
    /// Retained exact signed advertisement; renew explicitly before expiry.
    pub advertisement_file: PathBuf,
    /// One explicitly operated HTTPS route, ending exactly in /vhalla/v1.
    pub public_endpoint: Endpoint,
    /// One exact browser origin; credentials and cookies are unsupported.
    pub allowed_origin: CorsOrigin,
    /// Loopback only; use DEFAULT_LISTEN unless an explicit local port is needed.
    pub listen: SocketAddr,
}

/// Startup/listener failure, with no automatic creation or repair action.
#[derive(Debug)]
pub enum Error {
    /// Invalid listener, origin, route, file type or immutable configuration.
    Config,
    /// Invalid, incomplete or conflicting publisher state; preserve artifacts.
    State(&'static str),
    /// Publisher clock moved behind its durably retained last issuance.
    ClockRollback,
    /// Private publisher directory/file custody failed.
    Custody(vhalla_custody::Error),
    /// Independently pinned bootstrap validation failed.
    Bootstrap,
    /// Signed advertisement is invalid, stale or disagrees with configured key/route.
    Advertisement,
    /// Existing key custody could not be opened safely.
    Identity(vhalla_identity::IdentityError),
    /// Journal publication is inconsistent with the derived genesis.
    Journal(PublishedReadError),
    /// Filesystem, clock or socket operation failed.
    Io(io::Error),
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "public peer: {self:?}")
    }
}
impl std::error::Error for Error {}
impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Read-only service and retained native application-key custody.
pub struct Peer {
    config: Config,
    network: [u8; 32],
    identity: Identity,
    bootstrap: Bytes,
    advertisement: Mutex<RetainedAdvertisement>,
    journal: Journal<FsStore>,
    admission: Arc<Admission>,
    managed: bool,
    activity: Mutex<Option<activity::Owner>>,
    discovery: Mutex<Option<discovery::DiscoveryService>>,
}
impl Peer {
    /// Validate files and configured identities before any bind. File reads are
    /// regular-descriptor bounded; genesis is derived from the pinned artifact.
    /// Only the journal tip and first published bundle are structurally checked
    /// here. Clients independently verify every returned certificate and replay.
    pub fn open(config: Config) -> Result<Self, Error> {
        let loaded = Self::load(&config)?;
        let identity = Identity::open(&config.identity_dir).map_err(Error::Identity)?;
        let advertisement = read_regular(&config.advertisement_file, MAX_ADVERTISEMENT_BYTES)?;
        Self::finish(config, loaded, identity, advertisement, false)
    }
    fn load(config: &Config) -> Result<Loaded, Error> {
        if !config.listen.ip().is_loopback() || config.public_endpoint.scheme() != Scheme::Https {
            return Err(Error::Config);
        }
        let raw = read_regular(&config.bootstrap_file, MAX_BOOTSTRAP_BYTES)?;
        let bootstrap =
            Bootstrap::decode(&raw, config.bootstrap_pin).map_err(|_| Error::Bootstrap)?;
        let network = bootstrap.network_id();
        let client =
            CertifiedClient::new(bootstrap, config.bootstrap_pin).map_err(|_| Error::Bootstrap)?;
        let genesis = client.frontier().commitment();
        let journal = Journal::with_genesis(&config.journal_dir, FsStore, genesis);
        journal
            .read_published_range(PublishedRange {
                after_height: 0,
                expected_predecessor: Some(genesis),
                max_bundles: 1,
                max_bytes: vhalla_journal::MAX_PUBLISHED_PAGE_BYTES,
            })
            .map_err(Error::Journal)?;
        Ok(Loaded {
            raw,
            network,
            journal,
        })
    }
    fn finish(
        config: Config,
        loaded: Loaded,
        identity: Identity,
        advertisement: Vec<u8>,
        managed: bool,
    ) -> Result<Self, Error> {
        Self::finish_with_activity(config, loaded, identity, advertisement, managed, None)
    }
    fn finish_with_activity(
        config: Config,
        loaded: Loaded,
        identity: Identity,
        advertisement: Vec<u8>,
        managed: bool,
        activity: Option<activity::Owner>,
    ) -> Result<Self, Error> {
        let capabilities = if activity.is_some() {
            Capabilities::from_bits(Capabilities::READ.bits() | Capabilities::PUBLISH.bits())
                .map_err(|_| Error::Config)?
        } else {
            Capabilities::READ
        };
        let Loaded {
            raw,
            network,
            journal,
        } = loaded;
        let parsed = PeerAdvertisement::decode(&advertisement).map_err(|_| Error::Advertisement)?;
        let verified = parsed
            .verify(
                &VerificationPolicy {
                    network,
                    now: now()?,
                    max_clock_skew_seconds: MAX_CLOCK_SKEW_SECONDS,
                    max_ttl_seconds: MAX_TTL_SECONDS,
                },
                None,
            )
            .map_err(|_| Error::Advertisement)?;
        let claims = verified.claims();
        if claims.application_key != identity.public_key()
            || claims.capabilities != capabilities
            || claims.endpoints.as_slice() != [config.public_endpoint.clone()]
        {
            return Err(Error::Advertisement);
        }
        Ok(Self {
            config,
            network,
            identity,
            bootstrap: Bytes::from(raw),
            advertisement: Mutex::new(RetainedAdvertisement {
                raw: Bytes::from(advertisement),
                floor: verified.sequence_anchor(),
                serving: true,
            }),
            journal,
            admission: Arc::new(Admission::default()),
            managed,
            activity: Mutex::new(activity),
            discovery: Mutex::new(None),
        })
    }
    /// Full custody application key, also required by browser proof verification.
    pub fn application_key(&self) -> [u8; 32] {
        self.identity.public_key()
    }
    /// Stable immutable-origin network scope.
    pub const fn network_id(&self) -> [u8; 32] {
        self.network
    }
    /// Sign a bounded renewal for this configured network, full custody key,
    /// READ service and exact endpoint. The process-owned publisher must reserve
    /// and durably persist a strictly increasing sequence BEFORE signing, then
    /// atomically publish and sync these exact bytes. This method does no I/O,
    /// invents no counter, and does not install or publish the result.
    pub fn sign_advertisement(
        &self,
        sequence: u64,
        issued_at: u64,
        expires_at: u64,
    ) -> Result<PeerAdvertisement, Error> {
        let unsigned = vhalla_public_protocol::UnsignedAdvertisement::new(
            vhalla_public_protocol::AdvertisementClaims {
                network: self.network,
                application_key: self.identity.public_key(),
                sequence,
                issued_at,
                expires_at,
                protocol: vhalla_public_protocol::PROTOCOL_VERSION,
                capabilities: Capabilities::READ,
                endpoints: vec![self.config.public_endpoint.clone()],
            },
        )
        .map_err(|_| Error::Advertisement)?;
        self.identity
            .sign_public_advertisement(unsigned)
            .map_err(|_| Error::Advertisement)
    }

    /// Bind only the already validated loopback address.
    pub async fn bind(self: Arc<Self>) -> Result<BoundPeer, Error> {
        let listener = TcpListener::bind(self.config.listen).await?;
        Ok(BoundPeer {
            peer: self,
            listener,
        })
    }
    fn check_request<B>(&self, request: &Request<B>) -> Result<ReadRequest, StatusCode> {
        if request.method() != Method::GET {
            return Err(StatusCode::METHOD_NOT_ALLOWED);
        }
        if request.version() != hyper::Version::HTTP_11
            || request.uri().scheme().is_some()
            || request.uri().authority().is_some()
        {
            return Err(StatusCode::BAD_REQUEST);
        }
        let headers = request.headers();
        for name in [
            header::COOKIE,
            header::AUTHORIZATION,
            header::PROXY_AUTHORIZATION,
            header::TRANSFER_ENCODING,
            header::EXPECT,
            header::UPGRADE,
        ] {
            if headers.contains_key(name) {
                return Err(StatusCode::BAD_REQUEST);
            }
        }
        if let Some(value) = single(headers, header::CONTENT_LENGTH.as_str())? {
            if value != "0" {
                return Err(StatusCode::BAD_REQUEST);
            }
        }
        let expected_host = self
            .config
            .public_endpoint
            .as_str()
            .strip_prefix("https://")
            .and_then(|s| s.strip_suffix("/vhalla/v1"))
            .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
        let host = single(headers, header::HOST.as_str())?;
        if host.is_none()
            || (host != Some(expected_host) && host != expected_host.strip_suffix(":443"))
        {
            return Err(StatusCode::MISDIRECTED_REQUEST);
        }
        if let Some(origin) = single(headers, header::ORIGIN.as_str())? {
            if origin != self.config.allowed_origin.as_str() {
                return Err(StatusCode::FORBIDDEN);
            }
        }
        ReadRequest::parse_target(request.uri().path_and_query().map_or("", |p| p.as_str()))
            .map_err(|_| StatusCode::BAD_REQUEST)
    }
    fn answer(&self, request: ReadRequest) -> Result<(Bytes, String), StatusCode> {
        let body = match request.kind() {
            ReadKind::Advertisement => self.current_advertisement()?,
            ReadKind::Bootstrap => self.bootstrap.clone(),
            ReadKind::Bundles {
                after,
                frontier,
                count,
                bytes,
            } => {
                let page =
                    self.journal
                        .read_published_range(PublishedRange {
                            after_height: after,
                            expected_predecessor: Some(frontier),
                            max_bundles: usize::from(count),
                            max_bytes: bytes as usize,
                        })
                        .map_err(|error| match error {
                            PublishedReadError::CursorAhead { .. }
                            | PublishedReadError::FrontierMismatch { .. } => StatusCode::CONFLICT,
                            PublishedReadError::BudgetTooSmall { .. }
                            | PublishedReadError::Limits => StatusCode::BAD_REQUEST,
                            _ => StatusCode::SERVICE_UNAVAILABLE,
                        })?;
                let head = page.observed_head();
                let bundles = page.bundles().iter().map(|b| b.bytes().to_vec()).collect();
                Bytes::from(
                    BundlePage::new(&request, head.height, head.next, bundles)
                        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
                        .encode(),
                )
            }
        };
        let unsigned =
            UnsignedResponse::new(self.network, self.identity.public_key(), request, &body)
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        let proof = self
            .identity
            .sign_public_response(unsigned)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        Ok((body, hex(&proof.encode())))
    }
    fn current_advertisement(&self) -> Result<Bytes, StatusCode> {
        if self.managed {
            let retained = self
                .advertisement
                .lock()
                .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
            if !retained.serving {
                return Err(StatusCode::SERVICE_UNAVAILABLE);
            }
            let parsed = PeerAdvertisement::decode(&retained.raw)
                .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
            parsed
                .verify(
                    &VerificationPolicy {
                        network: self.network,
                        now: now().map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?,
                        max_clock_skew_seconds: MAX_CLOCK_SKEW_SECONDS,
                        max_ttl_seconds: MAX_TTL_SECONDS,
                    },
                    None,
                )
                .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
            return Ok(retained.raw.clone());
        }

        let raw = read_regular(&self.config.advertisement_file, MAX_ADVERTISEMENT_BYTES)
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        let parsed =
            PeerAdvertisement::decode(&raw).map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        let mut retained = self
            .advertisement
            .lock()
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        let unchanged = retained.raw.as_ref() == raw;
        let verified = parsed
            .verify(
                &VerificationPolicy {
                    network: self.network,
                    now: now().map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?,
                    max_clock_skew_seconds: MAX_CLOCK_SKEW_SECONDS,
                    max_ttl_seconds: MAX_TTL_SECONDS,
                },
                if unchanged {
                    None
                } else {
                    Some(&retained.floor)
                },
            )
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        let claims = verified.claims();
        if claims.application_key != self.identity.public_key()
            || claims.capabilities != Capabilities::READ
            || claims.endpoints.as_slice() != [self.config.public_endpoint.clone()]
        {
            return Err(StatusCode::SERVICE_UNAVAILABLE);
        }
        if !unchanged {
            *retained = RetainedAdvertisement {
                raw: Bytes::from(raw),
                floor: verified.sequence_anchor(),
                serving: true,
            };
        }
        Ok(retained.raw.clone())
    }
    async fn handle(
        self: Arc<Self>,
        request: Request<Incoming>,
        permit: Arc<Permit>,
    ) -> Result<Response<Full<Bytes>>, Infallible> {
        if matches!(
            request.uri().path(),
            "/vhalla/v1/peers" | "/vhalla/v1/peers/challenge" | "/vhalla/v1/peers/register"
        ) {
            return self.handle_discovery(request, permit).await;
        }
        if request.uri().path() == "/vhalla/v1/continuity" {
            return self.handle_continuity(request, permit).await;
        }
        if request.uri().path() == "/vhalla/v1/activity" {
            return self.handle_activity(request, permit).await;
        }
        let request = match self.check_request(&request) {
            Ok(request) => request,
            Err(status) => return Ok(failure(status)),
        };
        let origin = self.config.allowed_origin.as_str().to_owned();
        // Blocking reads retain admission even if the socket deadline fires.
        // A stuck filesystem cannot accumulate an unbounded abandoned job queue.
        let work = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            self.answer(request)
        });
        let result = timeout(READ_TIMEOUT, work).await;
        let response = match result {
            Ok(Ok(Ok((body, proof)))) => {
                let mut response = Response::new(Full::new(body));
                let headers = response.headers_mut();
                headers.insert(
                    header::CONTENT_TYPE,
                    header::HeaderValue::from_static("application/octet-stream"),
                );
                headers.insert(
                    header::CACHE_CONTROL,
                    header::HeaderValue::from_static("no-store"),
                );
                headers.insert(
                    header::CONNECTION,
                    header::HeaderValue::from_static("close"),
                );
                headers.insert(header::VARY, header::HeaderValue::from_static("Origin"));
                headers.insert(
                    header::ACCESS_CONTROL_EXPOSE_HEADERS,
                    header::HeaderValue::from_static("x-vhalla-proof"),
                );
                headers.insert(
                    "x-content-type-options",
                    header::HeaderValue::from_static("nosniff"),
                );
                if let (Ok(proof), Ok(origin)) = (
                    header::HeaderValue::from_str(&proof),
                    header::HeaderValue::from_str(&origin),
                ) {
                    headers.insert(PROOF_HEADER, proof);
                    headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);
                } else {
                    return Ok(failure(StatusCode::INTERNAL_SERVER_ERROR));
                }
                response
            }
            Ok(Ok(Err(status))) => failure(status),
            _ => failure(StatusCode::SERVICE_UNAVAILABLE),
        };
        Ok(response)
    }
}

/// Bound local listener. Constructed only by Peer::bind after startup checks.
pub struct BoundPeer {
    peer: Arc<Peer>,
    listener: TcpListener,
}
impl BoundPeer {
    /// Actual local address, useful when explicitly choosing ephemeral port zero.
    pub fn local_addr(&self) -> Result<SocketAddr, Error> {
        Ok(self.listener.local_addr()?)
    }
    /// Run until the caller's shutdown future resolves. Every socket has one
    /// absolute deadline, one HTTP/1 request, bounded headers and admission.
    /// Shutdown stops accepting, then drains for at most 15 seconds. Stalled
    /// blocking disk reads may still retain custody and admission after return.
    pub async fn run(self, shutdown: impl Future<Output = ()>) -> Result<(), Error> {
        tokio::pin!(shutdown);
        let mut tasks = JoinSet::new();
        loop {
            tokio::select! {
                _ = &mut shutdown => {
                    // Stop accepting first, allow bounded in-flight replies to
                    // finish, then abort only connections past the drain bound.
                    let _ = timeout(CONNECTION_TIMEOUT, async {
                        while tasks.join_next().await.is_some() {}
                    }).await;
                    tasks.abort_all();
                    while tasks.join_next().await.is_some() {}
                    return Ok(());
                }
                _ = tasks.join_next(), if !tasks.is_empty() => {}
                incoming = self.listener.accept() => {
                    let (socket, address) = incoming?;
                    let Some(permit) = self.peer.admission.acquire(address.ip()) else { drop(socket); continue; };
                    let peer = self.peer.clone();
                    tasks.spawn(async move {
                        let retained = permit.clone();
                        let service = service_fn(move |request| peer.clone().handle(request, permit.clone()));
                        let mut builder = http1::Builder::new();
                        builder.keep_alive(false).max_headers(MAX_HEADERS).max_buf_size(HEADER_BYTES).timer(TokioTimer::new()).header_read_timeout(HEADER_TIMEOUT);
                        let _ = timeout(CONNECTION_TIMEOUT, builder.serve_connection(TokioIo::new(socket), service)).await;
                        drop(retained);
                    });
                }
            }
        }
    }
}

fn failure(status: StatusCode) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(Bytes::from_static(b"request unavailable\n")));
    *response.status_mut() = status;
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    response.headers_mut().insert(
        header::CONNECTION,
        header::HeaderValue::from_static("close"),
    );
    response
}
fn single<'a>(headers: &'a HeaderMap, name: &str) -> Result<Option<&'a str>, StatusCode> {
    let mut values = headers.get_all(name).iter();
    let first = values
        .next()
        .map(|v| v.to_str().map_err(|_| StatusCode::BAD_REQUEST))
        .transpose()?;
    if values.next().is_some() {
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(first)
}
fn now() -> Result<u64, Error> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|time| time.as_secs())
        .map_err(|_| Error::Config)
}
fn read_regular(path: &Path, max: usize) -> Result<Vec<u8>, Error> {
    let file: File = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > max as u64 {
        return Err(Error::Config);
    }
    let mut raw = Vec::new();
    file.take(max as u64 + 1).read_to_end(&mut raw)?;
    if raw.len() > max {
        return Err(Error::Config);
    }
    Ok(raw)
}
struct Loaded {
    raw: Vec<u8>,
    network: [u8; 32],
    journal: Journal<FsStore>,
}
struct RetainedAdvertisement {
    serving: bool,
    raw: Bytes,
    floor: SequenceAnchor,
}
#[derive(Default)]
struct Admission {
    active: Mutex<BTreeMap<IpAddr, usize>>,
}
impl Admission {
    fn acquire(self: &Arc<Self>, ip: IpAddr) -> Option<Arc<Permit>> {
        let mut active = self.active.lock().ok()?;
        if active.values().sum::<usize>() >= MAX_CONNECTIONS
            || active.get(&ip).copied().unwrap_or(0) >= MAX_CONNECTIONS_PER_IP
        {
            return None;
        }
        *active.entry(ip).or_default() += 1;
        Some(Arc::new(Permit {
            admission: self.clone(),
            ip,
        }))
    }
}
struct Permit {
    admission: Arc<Admission>,
    ip: IpAddr,
}
impl Drop for Permit {
    fn drop(&mut self) {
        if let Ok(mut active) = self.admission.active.lock() {
            if let Some(count) = active.get_mut(&self.ip) {
                *count -= 1;
                if *count == 0 {
                    active.remove(&self.ip);
                }
            }
        }
    }
}
#[cfg(test)]
mod tests;
