//! Explicit opt-in public activity. One integration mutex owns certified replay
//! and local stores. It does not lock an external consensus journal writer.
use super::*;
use http_body_util::BodyExt;
use std::time::Instant;
use vhalla_public_protocol::activity::{
    ActivityEntry, ActivityKind, ActivityPage, ActivityRequest, LocalReceipt,
    UnsignedActivityResponse,
};
use vhalla_room_activity::{AdmissionContext, RoomScope, SignedEvent, MAX_EVENT_BYTES};
use vhalla_room_activity_store::{Limits, Store};
use vhalla_rooms::RoomGenesisId;

/// Maximum explicit room stores held by one peer process.
pub const MAX_ACTIVITY_ROOMS: usize = 32;
/// Maximum certified journal bundles replayed during one activity operation.
pub const ACTIVITY_REPLAY_BUDGET: usize = 32;
const BODY_TIMEOUT: Duration = Duration::from_secs(5);
const RATE_WINDOW: Duration = Duration::from_secs(60);
const GLOBAL_POSTS: usize = 120;
const IP_POSTS: usize = 30;
const RATE_IPS: usize = 256;

/// An explicitly operated existing store; paths never come from a request.
#[derive(Clone, Debug)]
pub struct ActivityRoomConfig {
    /// Full room genesis in the peer's pinned network/realm/directory.
    pub room: RoomGenesisId,
    /// Existing private activity store directory. No creation or reset on enable.
    pub directory: PathBuf,
    /// Exact immutable store resource budgets, including capacity backpressure.
    pub limits: Limits,
}
/// Explicit opt-in activation. Existing read-only configurations stay read-only.
#[derive(Clone, Debug)]
pub struct ActivityConfig {
    /// Nonempty list of distinct full rooms; at most MAX_ACTIVITY_ROOMS.
    pub rooms: Vec<ActivityRoomConfig>,
}
pub(super) struct ActivityService {
    client: CertifiedClient,
    stores: BTreeMap<[u8; 32], Store>,
    rate: PostRate,
    #[cfg(test)]
    after_refresh: Option<Box<dyn FnOnce() + Send>>,
}
impl ActivityService {
    // Explicit operator activation is not connected yet; keep the tested boundary available.
    #[allow(dead_code)]
    pub(super) fn open(raw: &[u8], pin: [u8; 32], config: ActivityConfig) -> Result<Self, Error> {
        if config.rooms.is_empty() || config.rooms.len() > MAX_ACTIVITY_ROOMS {
            return Err(Error::Config);
        }
        let bootstrap = Bootstrap::decode(raw, pin).map_err(|_| Error::Bootstrap)?;
        let client = CertifiedClient::new(bootstrap, pin).map_err(|_| Error::Bootstrap)?;
        let mut stores = BTreeMap::new();
        for room in config.rooms {
            let scope = RoomScope {
                network: client.network_id(),
                realm: client.registry().realm(),
                directory: client.registry().directory(),
                room: room.room,
            };
            if stores.contains_key(room.room.as_bytes()) {
                return Err(Error::Config);
            }
            let store = Store::open(&room.directory, scope, room.limits, None).map_err(|_| {
                Error::State("activity store must exist with exact scope and limits")
            })?;
            stores.insert(*room.room.as_bytes(), store);
        }
        Ok(Self {
            client,
            stores,
            rate: PostRate::new(),
            #[cfg(test)]
            after_refresh: None,
        })
    }
    // Applied state comes only from independently pinned bootstrap and verified
    // certificates in the published journal, never a raw registry snapshot.
    fn refresh(&mut self, journal: &Journal<FsStore>) -> Result<(), StatusCode> {
        let base = self.client.frontier();
        let page = journal
            .read_published_range(PublishedRange {
                after_height: base.height,
                expected_predecessor: Some(base.commitment()),
                max_bundles: ACTIVITY_REPLAY_BUDGET,
                max_bytes: vhalla_journal::MAX_PUBLISHED_PAGE_BYTES,
            })
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        let observed = page.observed_head();
        for bundle in page.bundles() {
            let candidate = self
                .client
                .prepare(self.client.network_id(), bundle.bytes())
                .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
            // Journal publication already durably retained these exact bytes.
            self.client
                .commit_after_persist(candidate)
                .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        }
        if self.client.frontier().height != observed.height
            || self.client.frontier().commitment() != observed.next
        {
            return Err(StatusCode::SERVICE_UNAVAILABLE);
        }
        #[cfg(test)]
        if let Some(hook) = self.after_refresh.take() {
            hook();
        }
        self.check_current(journal)
    }
    // This final snapshot rejects observed advancement during catch-up. A
    // different process can still publish immediately afterward; the receipt
    // binds this observed local certified frontier, never global atomic latest.
    fn check_current(&self, journal: &Journal<FsStore>) -> Result<(), StatusCode> {
        let frontier = self.client.frontier();
        let page = journal
            .read_published_range(PublishedRange {
                after_height: frontier.height,
                expected_predecessor: Some(frontier.commitment()),
                max_bundles: 1,
                max_bytes: vhalla_journal::MAX_PUBLISHED_PAGE_BYTES,
            })
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        if page.observed_head().height != frontier.height
            || page.observed_head().next != frontier.commitment()
            || !page.bundles().is_empty()
        {
            return Err(StatusCode::SERVICE_UNAVAILABLE);
        }
        Ok(())
    }
    fn answer(
        &mut self,
        peer: &Peer,
        request: ActivityRequest,
        body: &[u8],
        source: IpAddr,
    ) -> Result<Vec<u8>, StatusCode> {
        if !self.stores.contains_key(&request.room()) {
            return Err(StatusCode::NOT_FOUND);
        }
        if matches!(request.kind(), ActivityKind::Post { .. })
            && !self.rate.admit(source, Instant::now())
        {
            return Err(StatusCode::TOO_MANY_REQUESTS);
        }
        self.refresh(&peer.journal)?;
        let frontier = self.client.frontier();
        match request.kind() {
            ActivityKind::Post { .. } => {
                request
                    .check_body(body)
                    .map_err(|_| StatusCode::BAD_REQUEST)?;
                let event = SignedEvent::decode(body)
                    .and_then(SignedEvent::verify)
                    .map_err(|_| StatusCode::BAD_REQUEST)?;
                if event.claims().scope.room.as_bytes() != &request.room()
                    || event.claims().scope.network != peer.network
                {
                    return Err(StatusCode::BAD_REQUEST);
                }
                // Recheck after signature work, immediately before taking the
                // immutable policy context into the durable store append.
                self.check_current(&peer.journal)?;
                let context = AdmissionContext::new(peer.network, self.client.registry())
                    .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
                let store = self
                    .stores
                    .get_mut(&request.room())
                    .ok_or(StatusCode::NOT_FOUND)?;
                // An exact old intent is a prior local decision, not a new
                // policy admission. Store append only recovers identical bytes.
                let head = if store.recovery_required().map_err(store_status)? {
                    None
                } else {
                    store
                        .author_head(event.claims().author)
                        .map_err(store_status)?
                };
                let stored = store
                    .append(event, head, &context, *context.registry_digest())
                    .map_err(store_status)?;
                LocalReceipt::new(
                    stored.event(),
                    stored.cursor(),
                    *stored.registry_digest(),
                    frontier.height,
                    frontier.commitment(),
                    stored.reconciled(),
                )
                .map(|receipt| receipt.encode())
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
            }
            ActivityKind::Page { after, count } => {
                if !body.is_empty() {
                    return Err(StatusCode::BAD_REQUEST);
                }
                let store = self
                    .stores
                    .get(&request.room())
                    .ok_or(StatusCode::NOT_FOUND)?;
                let page = store
                    .read_page(after, usize::from(count))
                    .map_err(store_status)?;
                let entries = page
                    .records()
                    .iter()
                    .map(|stored| {
                        ActivityEntry::new(
                            stored.cursor(),
                            *stored.registry_digest(),
                            stored.event().clone(),
                        )
                    })
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
                ActivityPage::new(
                    &request,
                    page.tip().count(),
                    frontier.height,
                    frontier.commitment(),
                    entries,
                )
                .map(|page| page.encode())
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
            }
        }
    }
}
impl Peer {
    fn activity_answer(
        &self,
        request: ActivityRequest,
        body: &[u8],
        source: IpAddr,
    ) -> Result<(Bytes, String), StatusCode> {
        self.current_advertisement()?;
        let mut slot = self
            .activity
            .try_lock()
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        let service = slot.as_mut().ok_or(StatusCode::NOT_FOUND)?;
        let body = service.answer(self, request, body, source)?;
        let unsigned =
            UnsignedActivityResponse::new(self.network, self.identity.public_key(), request, &body)
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        let proof = self
            .identity
            .sign_activity_response(unsigned)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        Ok((Bytes::from(body), hex(&proof.encode())))
    }
    fn check_activity_request<B>(
        &self,
        request: &Request<B>,
    ) -> Result<(ActivityRequest, bool, Option<usize>), StatusCode> {
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
            header::EXPECT,
            header::UPGRADE,
            header::CONTENT_ENCODING,
        ] {
            if headers.contains_key(name) {
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
        let typed = ActivityRequest::parse_target(
            request.uri().path_and_query().map_or("", |p| p.as_str()),
        )
        .map_err(|_| StatusCode::BAD_REQUEST)?;
        let preflight = request.method() == Method::OPTIONS;
        let method = match typed.kind() {
            ActivityKind::Post { .. } => Method::POST,
            ActivityKind::Page { .. } => Method::GET,
        };
        if !preflight && request.method() != method {
            return Err(StatusCode::METHOD_NOT_ALLOWED);
        }
        let length = single(headers, header::CONTENT_LENGTH.as_str())?
            .map(|value| {
                if value.is_empty()
                    || (value.len() > 1 && value.starts_with('0'))
                    || !value.bytes().all(|b| b.is_ascii_digit())
                {
                    return Err(StatusCode::BAD_REQUEST);
                }
                value.parse::<usize>().map_err(|_| StatusCode::BAD_REQUEST)
            })
            .transpose()?;
        let transfer = single(headers, header::TRANSFER_ENCODING.as_str())?;
        if transfer.is_some() && (transfer != Some("chunked") || length.is_some()) {
            return Err(StatusCode::BAD_REQUEST);
        }
        if preflight {
            if single(headers, header::ORIGIN.as_str())?.is_none()
                || single(headers, header::ACCESS_CONTROL_REQUEST_METHOD.as_str())?
                    != Some(method.as_str())
                || single(headers, header::ACCESS_CONTROL_REQUEST_HEADERS.as_str())?
                    .is_some_and(|value| value != "content-type")
                || transfer.is_some()
                || length.is_some_and(|n| n != 0)
            {
                return Err(StatusCode::BAD_REQUEST);
            }
        } else if method == Method::POST {
            if single(headers, header::CONTENT_TYPE.as_str())? != Some("application/octet-stream") {
                return Err(StatusCode::UNSUPPORTED_MEDIA_TYPE);
            }
            if length.is_some_and(|n| n == 0 || n > MAX_EVENT_BYTES) {
                return Err(StatusCode::PAYLOAD_TOO_LARGE);
            }
            if length.is_none() && transfer.is_none() {
                return Err(StatusCode::LENGTH_REQUIRED);
            }
        } else if transfer.is_some() || length.is_some_and(|n| n != 0) {
            return Err(StatusCode::BAD_REQUEST);
        }
        Ok((typed, preflight, length))
    }
    pub(super) async fn handle_activity(
        self: Arc<Self>,
        request: Request<Incoming>,
        permit: Arc<Permit>,
    ) -> Result<Response<Full<Bytes>>, Infallible> {
        let (typed, preflight, length) = match self.check_activity_request(&request) {
            Ok(value) => value,
            Err(status) => return Ok(failure(status)),
        };
        let origin = self.config.allowed_origin.as_str().to_owned();
        match self.activity.try_lock() {
            Ok(slot) if slot.is_none() => {
                return Ok(activity_failure(StatusCode::NOT_FOUND, &origin))
            }
            Err(_) => return Ok(activity_failure(StatusCode::SERVICE_UNAVAILABLE, &origin)),
            Ok(_) => {}
        }
        if preflight {
            let mut response = Response::new(Full::new(Bytes::new()));
            *response.status_mut() = StatusCode::NO_CONTENT;
            cors(response.headers_mut(), &origin);
            response.headers_mut().insert(
                header::ACCESS_CONTROL_ALLOW_METHODS,
                header::HeaderValue::from_static("GET, POST"),
            );
            response.headers_mut().insert(
                header::ACCESS_CONTROL_ALLOW_HEADERS,
                header::HeaderValue::from_static("content-type"),
            );
            return Ok(response);
        }
        let body = match timeout(
            BODY_TIMEOUT,
            read_body(
                request.into_body(),
                length,
                matches!(typed.kind(), ActivityKind::Post { .. }),
            ),
        )
        .await
        {
            Ok(Ok(body)) => body,
            Ok(Err(status)) => return Ok(activity_failure(status, &origin)),
            Err(_) => return Ok(activity_failure(StatusCode::REQUEST_TIMEOUT, &origin)),
        };
        let source = permit.ip;
        let work = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            self.activity_answer(typed, &body, source)
        });
        let result = timeout(READ_TIMEOUT, work).await;
        let response = match result {
            Ok(Ok(Ok((body, proof)))) => {
                let mut response = Response::new(Full::new(body));
                cors(response.headers_mut(), &origin);
                if let Ok(proof) = header::HeaderValue::from_str(&proof) {
                    response.headers_mut().insert(PROOF_HEADER, proof);
                } else {
                    return Ok(activity_failure(StatusCode::INTERNAL_SERVER_ERROR, &origin));
                }
                response
            }
            Ok(Ok(Err(status))) => activity_failure(status, &origin),
            _ => activity_failure(StatusCode::SERVICE_UNAVAILABLE, &origin),
        };
        Ok(response)
    }
}
async fn read_body(
    mut body: Incoming,
    expected: Option<usize>,
    post: bool,
) -> Result<Vec<u8>, StatusCode> {
    let mut bytes = Vec::new();
    while let Some(frame) = body.frame().await {
        let data = frame
            .map_err(|_| StatusCode::BAD_REQUEST)?
            .into_data()
            .map_err(|_| StatusCode::BAD_REQUEST)?;
        let next = bytes
            .len()
            .checked_add(data.len())
            .filter(|n| *n <= if post { MAX_EVENT_BYTES } else { 0 })
            .ok_or(StatusCode::PAYLOAD_TOO_LARGE)?;
        bytes
            .try_reserve(data.len())
            .map_err(|_| StatusCode::PAYLOAD_TOO_LARGE)?;
        bytes.extend_from_slice(&data);
        debug_assert_eq!(bytes.len(), next);
    }
    if expected.is_some_and(|len| len != bytes.len()) || (post && bytes.is_empty()) {
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(bytes)
}
fn cors(headers: &mut HeaderMap, origin: &str) {
    for (name, value) in [
        (header::CONTENT_TYPE, "application/octet-stream"),
        (header::CACHE_CONTROL, "no-store"),
        (header::CONNECTION, "close"),
        (header::VARY, "Origin"),
        (header::ACCESS_CONTROL_EXPOSE_HEADERS, "x-vhalla-proof"),
    ] {
        headers.insert(name, header::HeaderValue::from_static(value));
    }
    headers.insert(
        "x-content-type-options",
        header::HeaderValue::from_static("nosniff"),
    );
    if let Ok(origin) = header::HeaderValue::from_str(origin) {
        headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);
    }
}
fn activity_failure(status: StatusCode, origin: &str) -> Response<Full<Bytes>> {
    let mut response = failure(status);
    cors(response.headers_mut(), origin);
    response
}
fn store_status(error: vhalla_room_activity_store::Error) -> StatusCode {
    use vhalla_room_activity_store::Error as E;
    match error {
        E::Capacity => StatusCode::INSUFFICIENT_STORAGE,
        E::Activity(vhalla_room_activity::Error::Policy) => StatusCode::FORBIDDEN,
        E::Activity(_) | E::Conflict => StatusCode::CONFLICT,
        _ => StatusCode::SERVICE_UNAVAILABLE,
    }
}
struct Window {
    at: Instant,
    count: usize,
}
struct PostRate {
    global: Window,
    ips: BTreeMap<IpAddr, Window>,
}
impl PostRate {
    // Used by the explicitly activated service constructor above.
    #[allow(dead_code)]
    fn new() -> Self {
        Self {
            global: Window {
                at: Instant::now(),
                count: 0,
            },
            ips: BTreeMap::new(),
        }
    }
    fn admit(&mut self, ip: IpAddr, now: Instant) -> bool {
        if now.duration_since(self.global.at) >= RATE_WINDOW {
            self.global = Window { at: now, count: 0 };
        }
        self.ips
            .retain(|_, window| now.duration_since(window.at) < RATE_WINDOW);
        if self.global.count >= GLOBAL_POSTS
            || (!self.ips.contains_key(&ip) && self.ips.len() >= RATE_IPS)
        {
            return false;
        }
        let window = self.ips.entry(ip).or_insert(Window { at: now, count: 0 });
        if window.count >= IP_POSTS {
            return false;
        }
        window.count += 1;
        self.global.count += 1;
        true
    }
}
#[cfg(test)]
mod tests;
