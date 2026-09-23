//! Worker-only, same-origin gateway fetch. No room keys or upstream TLS token.
use js_sys::{Reflect, Uint8Array};
use std::cell::{Cell, RefCell};
use vhalla_private_relay::codec;
use wasm_bindgen::{closure::Closure, JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::{
    AbortController, DedicatedWorkerGlobalScope, ReferrerPolicy, RequestCache, RequestCredentials,
    RequestInit, RequestMode, RequestRedirect, Response,
};
use zeroize::Zeroizing;

thread_local! {
    static ACTIVE: RefCell<Option<AbortController>> = const { RefCell::new(None) };
    static CANCELED: Cell<bool> = const { Cell::new(false) };
}
pub(super) fn canceled() -> bool {
    CANCELED.with(Cell::get)
}
pub(super) fn abort() {
    CANCELED.with(|flag| flag.set(true));
    ACTIVE.with(|slot| {
        if let Some(controller) = slot.borrow_mut().take() {
            controller.abort();
        }
    });
}
pub(super) use super::engine::TransportError as Error;
struct Attempt {
    scope: DedicatedWorkerGlobalScope,
    controller: AbortController,
    timer: i32,
    callback: Closure<dyn FnMut()>,
}
impl Drop for Attempt {
    fn drop(&mut self) {
        self.scope.clear_timeout_with_handle(self.timer);
        self.controller.abort();
        ACTIVE.with(|slot| {
            slot.borrow_mut().take();
        });
        let _ = &self.callback;
    }
}
pub(super) fn origin() -> Result<String, Error> {
    let global = js_sys::global();
    let location = Reflect::get(&global, &"location".into()).map_err(|_| Error::Refused)?;
    Reflect::get(&location, &"origin".into())
        .map_err(|_| Error::Refused)?
        .as_string()
        .ok_or(Error::Refused)
}
pub(super) fn canonical_origin(origin: &str) -> bool {
    let Some(port) = origin.strip_prefix("http://127.0.0.1:") else {
        return false;
    };
    port.parse::<u16>()
        .is_ok_and(|n| n != 0 && n.to_string() == port)
}
pub(super) async fn exchange(
    origin: &str,
    namespace: &[u8; 32],
    capability: &Zeroizing<String>,
    frame: &[u8],
    maximum: usize,
) -> Result<Vec<u8>, Error> {
    if canceled()
        || !canonical_origin(origin)
        || self::origin()? != origin
        || frame.len() > codec::MAX_REQUEST + 4
        || maximum > codec::MAX_RESPONSE + 4
    {
        return Err(Error::Refused);
    }
    let scope = js_sys::global()
        .dyn_into::<DedicatedWorkerGlobalScope>()
        .map_err(|_| Error::Refused)?;
    let controller = AbortController::new().map_err(|_| Error::Refused)?;
    let cancel = controller.clone();
    let callback = Closure::new(move || cancel.abort());
    let timer = scope
        .set_timeout_with_callback_and_timeout_and_arguments_0(
            callback.as_ref().unchecked_ref(),
            10_000,
        )
        .map_err(|_| Error::Refused)?;
    ACTIVE.with(|slot| *slot.borrow_mut() = Some(controller.clone()));
    let attempt = Attempt {
        scope,
        controller,
        timer,
        callback,
    };
    let init = RequestInit::new();
    init.set_method("POST");
    init.set_mode(RequestMode::SameOrigin);
    init.set_credentials(RequestCredentials::Omit);
    init.set_redirect(RequestRedirect::Error);
    init.set_cache(RequestCache::NoStore);
    // SameOrigin mode + NoReferrer policy serializes a POST Origin as null.
    // An empty explicit referrer suppresses Referer while SameOrigin policy
    // preserves the exact Origin required by the gateway's CSRF boundary.
    init.set_referrer_policy(ReferrerPolicy::SameOrigin);
    init.set_referrer("");
    init.set_signal(Some(&attempt.controller.signal()));
    init.set_body(Uint8Array::from(frame).as_ref());
    let headers = web_sys::Headers::new().map_err(|_| Error::Refused)?;
    headers
        .set("Content-Type", "application/octet-stream")
        .map_err(|_| Error::Refused)?;
    let authorization = Zeroizing::new(format!("Bearer {}", capability.as_str()));
    headers
        .set("Authorization", &authorization)
        .map_err(|_| Error::Refused)?;
    headers
        .set(
            "X-Vhalla-Namespace",
            &namespace
                .iter()
                .map(|v| format!("{v:02x}"))
                .collect::<String>(),
        )
        .map_err(|_| Error::Refused)?;
    init.set_headers(headers.as_ref());
    let response = JsFuture::from(
        attempt
            .scope
            .fetch_with_str_and_init(&format!("{origin}/private-relay/v1"), &init),
    )
    .await
    .map_err(|_| Error::Retry)?
    .dyn_into::<Response>()
    .map_err(|_| Error::Refused)?;
    if response.redirected() {
        return Err(Error::Refused);
    }
    if response.status() == 403 {
        // A changed host capability ends this worker. The caller must unlock
        // and explicitly supply current authority; retained budgets stay spent.
        return Err(Error::Authorization);
    }
    if matches!(response.status(), 408 | 429) || response.status() >= 500 {
        return Err(Error::Retry);
    }
    if response.status() != 200
        || response
            .headers()
            .get("content-type")
            .map_err(|_| Error::Refused)?
            .as_deref()
            != Some("application/octet-stream")
    {
        return Err(Error::Refused);
    }
    if response
        .headers()
        .get("content-length")
        .map_err(|_| Error::Refused)?
        .is_some_and(|v| v.parse::<usize>().map_or(true, |n| n > maximum))
    {
        return Err(Error::Refused);
    }
    let reader = response
        .body()
        .ok_or(Error::Refused)?
        .get_reader()
        .dyn_into::<web_sys::ReadableStreamDefaultReader>()
        .map_err(|_| Error::Refused)?;
    let mut raw = Vec::new();
    loop {
        if attempt.controller.signal().aborted() {
            return Err(Error::Retry);
        }
        let item = JsFuture::from(reader.read())
            .await
            .map_err(|_| Error::Retry)?;
        let done = Reflect::get(&item, &JsValue::from_str("done"))
            .map_err(|_| Error::Refused)?
            .as_bool()
            .ok_or(Error::Refused)?;
        if done {
            break;
        }
        let bytes = Reflect::get(&item, &JsValue::from_str("value"))
            .map_err(|_| Error::Refused)?
            .dyn_into::<Uint8Array>()
            .map_err(|_| Error::Refused)?;
        let next = raw
            .len()
            .checked_add(bytes.length() as usize)
            .filter(|n| *n <= maximum)
            .ok_or(Error::Refused)?;
        let old = raw.len();
        raw.resize(next, 0);
        bytes.copy_to(&mut raw[old..]);
    }
    reader.release_lock();
    if attempt.controller.signal().aborted() {
        return Err(Error::Retry);
    }
    Ok(raw)
}
