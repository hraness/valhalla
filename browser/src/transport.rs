//! Browser fetch boundary for explicitly selected, signed HTTPS routes.
//!
//! DNS/socket address pinning is unavailable in browser Fetch. This module does
//! not automatically dial third-party discovered routes, grant peer authority,
//! or treat a peer-authenticated body as a certified application result.
use js_sys::{Reflect, Uint8Array};
use vhalla_public_protocol::response::{
    proof_from_hex, ReadKind, ReadRequest, MAX_BOOTSTRAP_RESPONSE_BYTES, MAX_PAGE_FRAME_BYTES,
    PROOF_HEADER,
};
use vhalla_public_protocol::{Endpoint, Scheme, API_BASE, MAX_ADVERTISEMENT_BYTES};
use wasm_bindgen::{closure::Closure, JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::{
    AbortController, Performance, ReferrerPolicy, RequestCache, RequestCredentials, RequestInit,
    RequestMode, RequestRedirect, Response, Window,
};

#[cfg(feature = "local-qualification")]
#[path = "qualification.rs"]
mod qualification;

const DEADLINE_MS: i32 = 15_000;

/// A bounded failure. Never renders peer-provided text as trusted UI content.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Browser,
    Route,
    Network,
    Deadline,
    Bounds,
    Response,
    Proof,
}

struct Attempt {
    window: Window,
    controller: AbortController,
    clock: Performance,
    deadline: f64,
    timer: i32,
    _callback: Closure<dyn FnMut()>,
}
impl Attempt {
    fn new() -> Result<Self, Error> {
        let window = web_sys::window().ok_or(Error::Browser)?;
        let clock = window.performance().ok_or(Error::Browser)?;
        let controller = AbortController::new().map_err(|_| Error::Browser)?;
        let abort = controller.clone();
        let callback = Closure::new(move || abort.abort());
        let timer = window
            .set_timeout_with_callback_and_timeout_and_arguments_0(
                callback.as_ref().unchecked_ref(),
                DEADLINE_MS,
            )
            .map_err(|_| Error::Browser)?;
        let deadline = clock.now() + f64::from(DEADLINE_MS);
        Ok(Self {
            window,
            controller,
            clock,
            deadline,
            timer,
            _callback: callback,
        })
    }
    fn check(&self) -> Result<(), Error> {
        if self.clock.now() >= self.deadline || self.controller.signal().aborted() {
            Err(Error::Deadline)
        } else {
            Ok(())
        }
    }
}
impl Drop for Attempt {
    fn drop(&mut self) {
        self.window.clear_timeout_with_handle(self.timer);
        self.controller.abort();
    }
}

/// Create a new cryptographically random challenge for this exact attempt.
pub fn request(kind: ReadKind) -> Result<ReadRequest, Error> {
    ReadRequest::new(nonce()?, kind).map_err(|_| Error::Bounds)
}

/// A new independent challenge, never reused for a later network attempt.
pub fn nonce() -> Result<[u8; 32], Error> {
    let window = web_sys::window().ok_or(Error::Browser)?;
    let mut nonce = [0; 32];
    window
        .crypto()
        .map_err(|_| Error::Browser)?
        .get_random_values_with_u8_array(&mut nonce)
        .map_err(|_| Error::Browser)?;
    Ok(nonce)
}

/// Read a bounded, nonce-bound response from a user-selected HTTPS peer route.
///
/// The caller must verify the signed advertisement and retain the full expected
/// key/network independently of this reply, then replay application certificates.
/// No cookies, referrer, credentials, redirects or ambient authorization are sent.
pub async fn read(
    route: &Endpoint,
    network: [u8; 32],
    peer: [u8; 32],
    request: &ReadRequest,
) -> Result<Vec<u8>, Error> {
    let max = match request.kind() {
        ReadKind::Advertisement => MAX_ADVERTISEMENT_BYTES,
        ReadKind::Bootstrap => MAX_BOOTSTRAP_RESPONSE_BYTES,
        ReadKind::Bundles { .. } => MAX_PAGE_FRAME_BYTES,
    };
    let (proof, body) = exchange(route, "GET", &request.target(), None, max).await?;
    proof_from_hex(&proof)
        .map_err(|_| Error::Proof)?
        .verify(network, peer, request, &body)
        .map_err(|_| Error::Proof)?;
    Ok(body)
}

/// Typed public activity operation; every reply authenticates this exact body
/// hash, room, nonce, method and full peer key. Application admission is separate.
pub struct ActivityReply {
    pub body: Vec<u8>,
    pub proof: vhalla_public_protocol::activity::ActivityResponseProof,
}

pub async fn activity(
    route: &Endpoint,
    network: [u8; 32],
    peer: [u8; 32],
    request: &vhalla_public_protocol::activity::ActivityRequest,
    body: Option<&[u8]>,
) -> Result<ActivityReply, Error> {
    use vhalla_public_protocol::activity::{self, ActivityKind};
    let (method, max) = match request.kind() {
        ActivityKind::Post { .. } => {
            request
                .check_body(body.ok_or(Error::Bounds)?)
                .map_err(|_| Error::Bounds)?;
            ("POST", activity::RECEIPT_BYTES)
        }
        ActivityKind::Page { .. } if body.is_none() => ("GET", activity::MAX_ACTIVITY_PAGE_BYTES),
        _ => return Err(Error::Bounds),
    };
    let (proof, response) = exchange(route, method, &request.target(), body, max).await?;
    let proof = activity::proof_from_hex(&proof).map_err(|_| Error::Proof)?;
    proof
        .verify(network, peer, request, &response)
        .map_err(|_| Error::Proof)?;
    Ok(ActivityReply {
        body: response,
        proof,
    })
}

/// Typed continuity exchange: one already-persisted request plus its exact
/// canonical body for mutations. The verified proof and raw reply are returned
/// so the caller can durably retain the original signed evidence.
pub async fn continuity(
    route: &Endpoint,
    peer: [u8; 32],
    request: &vhalla_public_protocol::continuity::Request,
    body: Option<&[u8]>,
) -> Result<(Vec<u8>, vhalla_public_protocol::continuity::ResponseProof), Error> {
    use vhalla_public_protocol::continuity::{Kind, MAX_REPLY_BYTES};
    match (request.kind(), body) {
        (Kind::Stage { .. } | Kind::Commit { .. }, Some(raw)) => {
            request.check_body(raw).map_err(|_| Error::Bounds)?;
        }
        (Kind::Status { .. } | Kind::Evidence { .. }, None) => (),
        _ => return Err(Error::Bounds),
    }
    let (proof, response) = exchange(
        route,
        request.method(),
        &request.target(),
        body,
        MAX_REPLY_BYTES,
    )
    .await?;
    let proof = vhalla_public_protocol::continuity::ResponseProof::from_hex(&proof)
        .map_err(|_| Error::Proof)?;
    proof
        .verify(peer, request, &response)
        .map_err(|_| Error::Proof)?;
    Ok((response, proof))
}

async fn exchange(
    route: &Endpoint,
    method: &str,
    target: &str,
    body: Option<&[u8]>,
    max: usize,
) -> Result<(String, Vec<u8>), Error> {
    if route.scheme() != Scheme::Https {
        return Err(Error::Route);
    }
    let origin = route.as_str().strip_suffix(API_BASE).ok_or(Error::Route)?;
    let url = request_url(origin, target)?;
    let attempt = Attempt::new()?;
    let init = RequestInit::new();
    init.set_method(method);
    if let Some(body) = body {
        let bytes = Uint8Array::from(body);
        init.set_body(bytes.as_ref());
        let headers = web_sys::Headers::new().map_err(|_| Error::Browser)?;
        headers
            .set("Content-Type", "application/octet-stream")
            .map_err(|_| Error::Browser)?;
        init.set_headers(headers.as_ref());
    }
    init.set_mode(RequestMode::Cors);
    init.set_credentials(RequestCredentials::Omit);
    init.set_redirect(RequestRedirect::Error);
    init.set_cache(RequestCache::NoStore);
    init.set_referrer_policy(ReferrerPolicy::NoReferrer);
    init.set_signal(Some(&attempt.controller.signal()));
    let response = JsFuture::from(attempt.window.fetch_with_str_and_init(&url, &init))
        .await
        .map_err(|_| Error::Network)?
        .dyn_into::<Response>()
        .map_err(|_| Error::Response)?;
    attempt.check()?;
    if response.status() != 200 || response.redirected() {
        return Err(Error::Response);
    }
    let proof = response
        .headers()
        .get(PROOF_HEADER)
        .map_err(|_| Error::Response)?
        .ok_or(Error::Proof)?;
    if let Some(length) = response
        .headers()
        .get("content-length")
        .map_err(|_| Error::Response)?
    {
        let length = length.parse::<u64>().map_err(|_| Error::Response)?;
        if length > max as u64 {
            return Err(Error::Bounds);
        }
    }
    let stream = response.body().ok_or(Error::Response)?;
    let reader = stream
        .get_reader()
        .dyn_into::<web_sys::ReadableStreamDefaultReader>()
        .map_err(|_| Error::Response)?;
    let mut body = Vec::new();
    loop {
        attempt.check()?;
        let item = JsFuture::from(reader.read())
            .await
            .map_err(|_| Error::Network)?;
        attempt.check()?;
        let done = Reflect::get(&item, &JsValue::from_str("done"))
            .map_err(|_| Error::Response)?
            .as_bool()
            .ok_or(Error::Response)?;
        if done {
            break;
        }
        let chunk = Reflect::get(&item, &JsValue::from_str("value"))
            .map_err(|_| Error::Response)?
            .dyn_into::<Uint8Array>()
            .map_err(|_| Error::Response)?;
        let len = chunk.length() as usize;
        let next = body
            .len()
            .checked_add(len)
            .filter(|size| *size <= max)
            .ok_or(Error::Bounds)?;
        body.try_reserve(len).map_err(|_| Error::Bounds)?;
        let old = body.len();
        body.resize(next, 0);
        chunk.copy_to(&mut body[old..]);
    }
    reader.release_lock();
    attempt.check()?;
    Ok((proof, body))
}

fn request_url(origin: &str, target: &str) -> Result<String, Error> {
    #[cfg(feature = "local-qualification")]
    {
        let location = web_sys::window().ok_or(Error::Browser)?.location();
        if !qualification::allows_page_origin(&location.origin().map_err(|_| Error::Browser)?) {
            return Err(Error::Route);
        }
        let name = match origin {
            "https://peer-a.vhalla.dev:443" => "peer-a",
            "https://peer-b.vhalla.dev:443" => "peer-b",
            "https://peer-c.vhalla.dev:443" => "peer-c",
            _ => return Err(Error::Route),
        };
        Ok(format!("/__qualification/{name}{target}"))
    }
    #[cfg(not(feature = "local-qualification"))]
    {
        Ok(format!("{origin}{target}"))
    }
}

/// Fetch only a discovery listing from an already explicitly selected peer.
/// Individual returned routes remain inert until the user selects them.
pub async fn discover(
    route: &Endpoint,
    network: [u8; 32],
    peer: [u8; 32],
    request: vhalla_public_protocol::discovery::DiscoveryRequest,
) -> Result<Vec<u8>, Error> {
    use vhalla_public_protocol::discovery::{
        DiscoveryKind, DiscoveryResponseProof, MAX_DISCOVERY_PROOF_BYTES, MAX_PEER_PAGE_BYTES,
    };
    if !matches!(request.kind(), DiscoveryKind::List { .. }) {
        return Err(Error::Bounds);
    }
    let (proof, body) =
        exchange(route, "GET", &request.target(), None, MAX_PEER_PAGE_BYTES).await?;
    if proof.len() > MAX_DISCOVERY_PROOF_BYTES * 2
        || !proof.len().is_multiple_of(2)
        || !proof
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(Error::Proof);
    }
    let bytes = (0..proof.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&proof[i..i + 2], 16).map_err(|_| Error::Proof))
        .collect::<Result<Vec<_>, _>>()?;
    DiscoveryResponseProof::decode(&bytes)
        .map_err(|_| Error::Proof)?
        .verify(network, peer, request, &body)
        .map_err(|_| Error::Proof)?;
    Ok(body)
}
