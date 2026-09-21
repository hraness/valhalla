use futures_channel::oneshot;
use js_sys::{Array, Uint8Array};
use std::{
    cell::{Cell, RefCell},
    future::{poll_fn, Future},
    rc::{Rc, Weak},
    task::{Poll, Waker},
};
use vhalla_browser_storage::{
    browser::{outbox::IndexedOutbox, IndexedStorage},
    identity::IdentitySnapshot,
    outbox::{AuthorHead, AuthorScope},
    Image, Namespace, Slot,
};
use vhalla_browser_vault::{Envelope, ENVELOPE_BYTES, MAX_PASSWORD_BYTES, MIN_PASSWORD_BYTES};
use vhalla_room_activity::{SignedEvent, UnsignedEvent, MAX_EVENT_BYTES};
use wasm_bindgen::{prelude::*, JsCast};
use wasm_bindgen_futures::{spawn_local, JsFuture};
use web_sys::{
    Document, Element, ErrorEvent, Event, HtmlAnchorElement, HtmlButtonElement, HtmlInputElement,
    MessageEvent, Performance, Worker,
};
use zeroize::Zeroizing;

#[cfg(feature = "private-rooms")]
#[path = "ui/private.rs"]
pub mod private;
#[cfg(all(feature = "private-rooms", feature = "local-qualification"))]
#[path = "ui/private_qualification.rs"]
pub mod private_qualification;
#[path = "ui/recovery.rs"]
mod recovery;
pub use recovery::{
    decrypt_author_page, download_author_part, encrypt_author_page, recovery_identity,
};

// A fixed local profile selected by this application, never by a peer or URL.
const PROFILE: [u8; 32] = *b"vhalla-browser-local-profile-v01";
const READY_MS: f64 = 30_000.0;
const STORAGE_MS: f64 = 30_000.0;
const KDF_MS: f64 = 120_000.0;
const MAX_RETIRED: usize = 4;
const MAX_DOWNLOADS: usize = 4;
type App = Rc<RefCell<State>>;
thread_local! {
    static IDENTITY: RefCell<Option<Weak<RefCell<State>>>> = const { RefCell::new(None) };
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Token {
    generation: u64,
    operation: u64,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Stage {
    ReadingFile,
    Worker,
    Saving,
    Signing,
    Authorizing,
    Backup,
    #[cfg(feature = "private-rooms")]
    Private,
}
#[derive(Default)]
struct Cancellation {
    canceled: Cell<bool>,
    waker: RefCell<Option<Waker>>,
}
impl Cancellation {
    fn cancel(&self) {
        self.canceled.set(true);
        let waker = self.waker.borrow_mut().take();
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}
// Dropping a canceled storage future activates its transaction/open cleanup;
// merely ignoring its eventual result would leave a write running indefinitely.
async fn cancellable<F: Future>(cancel: Rc<Cancellation>, future: F) -> Option<F::Output> {
    let mut future = Box::pin(future);
    poll_fn(|cx| {
        if cancel.canceled.get() {
            cancel.waker.borrow_mut().take();
            return Poll::Ready(None);
        }
        *cancel.waker.borrow_mut() = Some(cx.waker().clone());
        match future.as_mut().poll(cx) {
            Poll::Ready(value) => {
                cancel.waker.borrow_mut().take();
                Poll::Ready(Some(value))
            }
            Poll::Pending => Poll::Pending,
        }
    })
    .await
}
struct Pending {
    token: Token,
    stage: Stage,
    deadline: f64,
    cancel: Rc<Cancellation>,
    kind: PendingKind,
}
enum PendingKind {
    #[cfg(feature = "private-rooms")]
    Private {
        expected: private::Expected,
        reply: oneshot::Sender<Result<crate::private_wire::Response, String>>,
    },
    Vault {
        created: bool,
    },
    Activity {
        draft: UnsignedEvent,
        reply: oneshot::Sender<Result<SignedEvent, String>>,
    },
    Backup {
        expected: Option<vhalla_browser_vault::backup::AuthorBackupPage>,
        author: [u8; 32],
        reply: oneshot::Sender<Result<Vec<u8>, String>>,
    },
}
struct Callbacks {
    _message: Closure<dyn FnMut(MessageEvent)>,
    _error: Closure<dyn FnMut(ErrorEvent)>,
}
struct State {
    #[cfg(feature = "private-rooms")]
    private: private::PrivateState,
    document: Document,
    clock: Performance,
    storage: Option<IndexedStorage>,
    saved: IdentitySnapshot,
    worker: Option<Worker>,
    callbacks: Option<Callbacks>,
    // A worker callback may retire itself. Drop it on a later event-loop turn.
    retired: Vec<Callbacks>,
    generation: u64,
    operation: u64,
    ready: bool,
    unlocked: bool,
    failed: bool,
    loading: bool,
    load_cancel: Option<Rc<Cancellation>>,
    load_deadline: Option<f64>,
    ready_deadline: Option<f64>,
    pending: Option<Pending>,
    downloads: Vec<(String, f64)>,
}
impl State {
    fn busy(&self) -> bool {
        self.loading || self.pending.is_some() || !self.ready
    }
    fn can_operate_base(&self) -> bool {
        !self.failed && !self.busy() && self.storage.as_ref().is_some_and(|s| !s.needs_reopen())
    }
    fn can_operate(&self) -> bool {
        #[cfg(feature = "private-rooms")]
        if self.private.active {
            return false;
        }
        self.can_operate_base()
    }
    fn current(&self, token: Token, stage: Stage) -> bool {
        !self.failed
            && self.ready
            && self.worker.is_some()
            && self.generation == token.generation
            && self
                .pending
                .as_ref()
                .is_some_and(|p| p.token == token && p.stage == stage)
    }
}
fn element(app: &App, id: &str) -> Element {
    app.borrow()
        .document
        .get_element_by_id(id)
        .expect("static browser element")
}
fn input(app: &App, id: &str) -> HtmlInputElement {
    element(app, id).unchecked_into()
}
fn status(app: &App, message: &str, error: bool) {
    let el = element(app, "status");
    el.set_text_content(Some(message));
    let _ = el.set_attribute("data-error", if error { "true" } else { "false" });
}
fn render(app: &App) {
    let state = app.borrow();
    let can = state.can_operate();
    for (id, enabled) in [
        ("create", can && state.saved.vault().is_none()),
        (
            "unlock",
            can && state.saved.vault().is_some() && !state.unlocked,
        ),
        ("restore", can),
        ("backup", can && state.saved.vault().is_some()),
        ("lock", state.can_operate_base() && state.unlocked),
    ] {
        state
            .document
            .get_element_by_id(id)
            .expect("static button")
            .unchecked_into::<HtmlButtonElement>()
            .set_disabled(!enabled);
    }
    for id in ["password", "restore-file"] {
        state
            .document
            .get_element_by_id(id)
            .expect("static input")
            .unchecked_into::<HtmlInputElement>()
            .set_disabled(!can);
    }
    state
        .document
        .get_element_by_id("identity-state")
        .unwrap()
        .set_text_content(Some(if state.failed {
            "Reload required"
        } else if state.busy() {
            "Working"
        } else if state.unlocked {
            #[cfg(feature = "private-rooms")]
            {
                if state.private.active {
                    "Private custody"
                } else {
                    "Unlocked"
                }
            }
            #[cfg(not(feature = "private-rooms"))]
            {
                "Unlocked"
            }
        } else {
            "Locked"
        }));
    let summary = state.document.get_element_by_id("key-summary").unwrap();
    if let Some(image) = state.saved.vault() {
        let _ = summary.remove_attribute("hidden");
        if let Some(raw) = image.records().next() {
            if let Ok(envelope) = Envelope::from_bytes(raw) {
                state
                    .document
                    .get_element_by_id("public-key")
                    .unwrap()
                    .set_text_content(Some(&hex(&envelope.claimed_public_key())));
            }
        }
        let local = image
            .records()
            .next()
            .and_then(|raw| Envelope::from_bytes(raw).ok())
            .is_some_and(|envelope| {
                state
                    .saved
                    .local_creation(envelope.claimed_public_key())
                    .is_ok()
            });
        state.document.get_element_by_id("identity-help").unwrap().set_text_content(Some(if local {
            "Identity created here. Use one device for authoring and keep both your encrypted key backup and complete author-state parts for each room. A key backup alone does not recover signing history."
        } else {
            "Imported identity. Restore a complete author-state backup for each previously used room before writing. A key backup alone cannot authorize a fresh signing sequence."
        }));
        let _ = state
            .document
            .get_element_by_id("password")
            .unwrap()
            .set_attribute("autocomplete", "current-password");
    } else {
        let _ = summary.set_attribute("hidden", "");
    }
}
fn hex(raw: &[u8]) -> String {
    raw.iter().map(|b| format!("{b:02x}")).collect()
}
fn stop_worker(app: &App) {
    #[cfg(feature = "private-rooms")]
    crate::private_panel::clear_sensitive_state();
    let mut state = app.borrow_mut();
    state.generation = state.generation.saturating_add(1);
    if let Some(worker) = state.worker.take() {
        worker.set_onmessage(None);
        worker.set_onerror(None);
        worker.terminate();
    }
    if let Some(callbacks) = state.callbacks.take() {
        state.retired.push(callbacks);
    }
    state.ready = false;
    state.ready_deadline = None;
    state.unlocked = false;
    #[cfg(feature = "private-rooms")]
    state.private.stopped();
}
fn fail(app: &App, message: &str) {
    let (loading, pending, storage) = {
        let mut state = app.borrow_mut();
        state.failed = true;
        state.loading = false;
        state.load_deadline = None;
        (
            state.load_cancel.take(),
            state.pending.take().map(|p| p.cancel),
            state.storage.take(),
        )
    };
    stop_worker(app);
    if let Some(cancel) = loading {
        cancel.cancel();
    }
    if let Some(cancel) = pending {
        cancel.cancel();
    }
    drop(storage);
    input(app, "password").set_value("");
    status(app, message, true);
    render(app);
}
fn operation_error(app: &App, token: Token, stage: Stage, message: &str, restart: bool) {
    {
        let mut state = app.borrow_mut();
        if !state.current(token, stage) {
            return;
        }
        state.pending = None;
    }
    // An unsuccessful restore must not leave its uncommitted key in the worker.
    if restart && start_worker(app).is_err() {
        fail(
            app,
            "Identity locked. The worker could not restart; reload to retry.",
        );
        return;
    }
    status(app, message, true);
    render(app);
}
fn start_worker(app: &App) -> Result<(), JsValue> {
    stop_worker(app);
    let generation = {
        let state = app.borrow();
        if state.failed || state.retired.len() >= MAX_RETIRED || state.generation == u64::MAX {
            return Err(JsValue::NULL);
        }
        state.generation
    };
    // Trunk generates this loader and its imports; no authored JS or blob script.
    let worker = Worker::new("./vhalla-vault-worker_loader.js")?;
    let weak = Rc::downgrade(app);
    let message = Closure::<dyn FnMut(MessageEvent)>::new(move |event: MessageEvent| {
        let Some(app) = weak.upgrade() else {
            return;
        };
        if app.borrow().failed || app.borrow().generation != generation {
            return;
        }
        if !Array::is_array(&event.data()) {
            fail(
                &app,
                "The identity worker returned invalid data. Reload to retry.",
            );
            return;
        }
        let fields = Array::from(&event.data());
        match fields.get(0).as_string().as_deref() {
            #[cfg(feature = "private-rooms")]
            Some("private-reply") if fields.length() == 3 => private::finish(&app, &fields),
            #[cfg(feature = "private-rooms")]
            Some("private-error") if fields.length() == 1 => fail(
                &app,
                "Private custody refused or was interrupted. Preserve its exact locator, reload and reopen; never create replacement state.",
            ),
            Some("ready") if fields.length() == 1 => {
                {
                    let mut state = app.borrow_mut();
                    if state.ready {
                        drop(state);
                        fail(
                            &app,
                            "The identity worker returned an unexpected response. Reload to retry.",
                        );
                        return;
                    }
                    state.ready = true;
                    state.ready_deadline = None;
                }
                if generation == 1 && !app.borrow().loading {
                    status(
                        &app,
                        "Local workspace ready. Enter your password to unlock or create an identity.",
                        false,
                    );
                }
                render(&app);
            }
            Some("error") if fields.length() == 2 => {
                if app
                    .borrow()
                    .pending
                    .as_ref()
                    .is_some_and(|p| matches!(p.stage, Stage::Signing | Stage::Backup))
                {
                    fail(
                        &app,
                        "The identity operation failed. Preserve the reserved draft or backup parts and reload before retrying.",
                    );
                    return;
                }
                let token = app
                    .borrow()
                    .pending
                    .as_ref()
                    .filter(|p| p.stage == Stage::Worker)
                    .map(|p| p.token);
                let message = fields.get(1).as_string().filter(|v| v.len() <= 200);
                if let (Some(token), Some(message)) = (token, message) {
                    operation_error(&app, token, Stage::Worker, &message, true);
                } else {
                    fail(
                        &app,
                        "The identity worker returned an unexpected response. Reload to retry.",
                    );
                }
            }
            Some("unlocked") if fields.length() == 3 => {
                let raw = fields.get(1).dyn_into::<Uint8Array>();
                let public = fields.get(2).dyn_into::<Uint8Array>();
                let (Ok(raw), Ok(public)) = (raw, public) else {
                    fail(
                        &app,
                        "The identity worker returned invalid data. Reload to retry.",
                    );
                    return;
                };
                if raw.length() as usize != ENVELOPE_BYTES || public.length() != 32 {
                    fail(
                        &app,
                        "The identity worker returned invalid data. Reload to retry.",
                    );
                    return;
                }
                let token =
                    {
                        let mut state = app.borrow_mut();
                        let deadline = state.clock.now() + STORAGE_MS;
                        let Some(pending) = state.pending.as_mut().filter(|p| {
                            p.stage == Stage::Worker && p.token.generation == generation
                        }) else {
                            drop(state);
                            fail(
                            &app,
                            "The identity worker returned an unexpected response. Reload to retry.",
                        );
                            return;
                        };
                        pending.stage = Stage::Saving;
                        pending.deadline = deadline;
                        pending.token
                    };
                let raw = raw.to_vec();
                let public = public.to_vec();
                spawn_local(async move {
                    finish_unlock(&app, token, raw, public).await;
                });
            }
            Some("activity-signed") if fields.length() == 4 => {
                finish_activity(&app, &fields);
            }
            Some("author-page") if fields.length() == 3 => recovery::finish_page(&app, &fields),
            _ => fail(
                &app,
                "The identity worker returned invalid data. Reload to retry.",
            ),
        }
    });
    let weak = Rc::downgrade(app);
    let error = Closure::<dyn FnMut(ErrorEvent)>::new(move |event: ErrorEvent| {
        event.prevent_default();
        if let Some(app) = weak.upgrade() {
            if app.borrow().generation == generation && !app.borrow().failed {
                fail(
                    &app,
                    "The identity worker stopped. Reload to reconcile saved state before retrying.",
                );
            }
        }
    });
    worker.set_onmessage(Some(message.as_ref().unchecked_ref()));
    worker.set_onerror(Some(error.as_ref().unchecked_ref()));
    let mut state = app.borrow_mut();
    state.worker = Some(worker);
    state.callbacks = Some(Callbacks {
        _message: message,
        _error: error,
    });
    state.ready_deadline = Some(state.clock.now() + READY_MS);
    Ok(())
}
async fn finish_unlock(app: &App, token: Token, raw: Vec<u8>, public: Vec<u8>) {
    if !app.borrow().current(token, Stage::Saving) {
        return;
    }
    let Ok(envelope) = Envelope::from_bytes(&raw) else {
        fail(
            app,
            "The identity worker returned an invalid backup. Reload to retry.",
        );
        return;
    };
    if public.as_slice() != envelope.claimed_public_key() {
        fail(
            app,
            "The identity worker returned an inconsistent key. Reload to retry.",
        );
        return;
    }
    let previous = app.borrow().saved.clone();
    if let Some(previous) = previous.vault() {
        let same_key = previous
            .records()
            .next()
            .and_then(|v| Envelope::from_bytes(v).ok())
            .is_some_and(|v| v.claimed_public_key() == envelope.claimed_public_key());
        if !same_key {
            operation_error(
                app,
                token,
                Stage::Saving,
                "This backup belongs to a different identity. Use a separate browser profile; your saved identity was preserved.",
                true,
            );
            return;
        }
    }
    let Ok(next) = Image::new(Slot::Vault, &[&raw]) else {
        fail(
            app,
            "The identity worker returned an invalid backup. Reload to retry.",
        );
        return;
    };
    let (storage, cancel, created) = {
        let mut state = app.borrow_mut();
        let cancel = state.pending.as_ref().unwrap().cancel.clone();
        let created = matches!(
            state.pending.as_ref().unwrap().kind,
            PendingKind::Vault { created: true }
        );
        (state.storage.take(), cancel, created)
    };
    let Some(mut storage) = storage else {
        fail(app, "Local storage is unavailable. Reload before retrying.");
        return;
    };
    // An unchanged authenticated vault needs an exact readonly pair check, so
    // storage pressure cannot make its existing key unavailable for export.
    // Creation and changed same-key backup imports still require write CAS.
    let unchanged = !created && previous.vault() == Some(&next);
    let result = cancellable(cancel, async {
        if created {
            storage.create_local_identity(&next).await
        } else if unchanged {
            storage
                .revalidate_identity(&previous)
                .await
                .map_err(vhalla_browser_storage::PublishError::ReopenRequired)
        } else {
            storage.replace_identity(&previous, &next).await
        }
    })
    .await;
    if !app.borrow().current(token, Stage::Saving) {
        return;
    }
    if let Some(Ok(saved)) = result {
        {
            let mut state = app.borrow_mut();
            state.storage = Some(storage);
            state.saved = saved;
            state.unlocked = true;
            state.pending = None;
        }
        status(
            app,
            if unchanged {
                "Identity unlocked from its saved encrypted backup. Download and verify an independent backup."
            } else {
                "Identity unlocked and encrypted backup saved locally. Download and verify an independent backup."
            },
            false,
        );
        render(app);
    } else {
        fail(
            app,
            "Storage changed or the identity check was interrupted. Reload to reconcile it. Identity remains locked; no successful save has been claimed.",
        );
    }
}

struct OperationGuard {
    app: Weak<RefCell<State>>,
    token: Token,
    stage: Stage,
    message: &'static str,
}
impl Drop for OperationGuard {
    fn drop(&mut self) {
        if let Some(app) = self.app.upgrade() {
            let pending = app.borrow().current(self.token, self.stage);
            if pending {
                fail(&app, self.message);
            }
        }
    }
}

/// Return only the currently idle, unlocked, exact-CAS-authenticated identity.
/// This permits selecting an author, not initializing missing sequence state.
pub fn activity_author() -> Result<[u8; 32], String> {
    let app = IDENTITY
        .with(|slot| slot.borrow().as_ref().and_then(Weak::upgrade))
        .ok_or("Identity support is not ready.")?;
    let state = app.borrow();
    if !state.can_operate() || !state.unlocked {
        return Err("Unlock your identity and wait for its current operation to finish.".into());
    }
    state
        .saved
        .vault()
        .and_then(|image| image.records().next())
        .and_then(|raw| Envelope::from_bytes(raw).ok())
        .map(|envelope| envelope.claimed_public_key())
        .ok_or("The authenticated identity is unavailable. Reload before retrying.".into())
}

/// Initialize an unused local author scope in the same transaction that verifies
/// the exact saved vault and local creation record. The returned head is already
/// persisted; callers must not initialize it again. Existing state always wins.
///
/// Key-only restore cannot authorize this. Local provenance also cannot detect
/// use of an exported key on another device or coherent browser-storage rollback.
pub async fn authorize_fresh_activity_scope(scope: AuthorScope) -> Result<AuthorHead, String> {
    let public = activity_author()?;
    if public != scope.author() {
        return Err("This activity scope belongs to a different unlocked identity.".into());
    }
    let app = IDENTITY
        .with(|slot| slot.borrow().as_ref().and_then(Weak::upgrade))
        .ok_or("Identity support is not ready.")?;
    let expected = app.borrow().saved.clone();
    expected.local_creation(public).map_err(|_| {
        "This restored identity has no retained local creation proof. Activity stays read-only until its author sequence state is recovered.".to_owned()
    })?;
    let token = begin_operation(&app, Stage::Authorizing, STORAGE_MS)
        .ok_or("Identity is busy. Wait before initializing activity.")?;
    let cancel = app.borrow().pending.as_ref().unwrap().cancel.clone();
    let guard = OperationGuard {
        app: Rc::downgrade(&app),
        token,
        stage: Stage::Authorizing,
        message: "Author initialization was interrupted. Reload to reconcile retained activity state before retrying.",
    };
    status(
        &app,
        "Retaining this identity's initial activity sequence…",
        false,
    );
    render(&app);
    let result = cancellable(cancel, async {
        let mut outbox = IndexedOutbox::open(Namespace::new(PROFILE))
            .await
            .map_err(vhalla_browser_storage::PublishError::Rejected)?;
        outbox
            .initialize_locally_created_author(scope, &expected)
            .await
    })
    .await;
    if !app.borrow().current(token, Stage::Authorizing) {
        return Err(
            "Author initialization was interrupted. Reload and inspect retained activity state."
                .into(),
        );
    }
    let head = match result {
        Some(Ok(head)) => head,
        _ => {
            fail(
                &app,
                "Author state changed or initialization was interrupted. Reload to reconcile it; no sequence was reset.",
            );
            return Err(
                "Could not confirm author initialization. Reload and inspect retained state."
                    .into(),
            );
        }
    };
    app.borrow_mut().pending = None;
    status(
        &app,
        "Initial author sequence retained on this device. No activity has been signed or sent.",
        false,
    );
    render(&app);
    drop(guard);
    Ok(head)
}

/// Sign only an already-durably-reserved typed activity with the unlocked key.
/// The caller owns admission, reserve-before-sign, and atomic final publication;
/// success here means a strictly verified signature, never a saved/queued event.
pub async fn sign_activity(draft: UnsignedEvent) -> Result<SignedEvent, String> {
    let app = IDENTITY
        .with(|slot| slot.borrow().as_ref().and_then(Weak::upgrade))
        .ok_or("Identity support is not ready.")?;
    {
        let state = app.borrow();
        if !state.can_operate() || !state.unlocked {
            return Err(
                "Unlock your identity and wait for its current operation to finish.".into(),
            );
        }
        let authenticated = state
            .saved
            .vault()
            .and_then(|image| image.records().next())
            .and_then(|raw| Envelope::from_bytes(raw).ok())
            .is_some_and(|envelope| envelope.claimed_public_key() == draft.claims().author);
        if !authenticated {
            return Err("This activity belongs to a different unlocked identity.".into());
        }
    }
    let token = begin_operation(&app, Stage::Signing, READY_MS)
        .ok_or("The identity is busy. Preserve the reserved draft and retry.")?;
    let (sender, receiver) = oneshot::channel();
    let bytes = draft.encode();
    app.borrow_mut().pending.as_mut().unwrap().kind = PendingKind::Activity {
        draft,
        reply: sender,
    };
    let guard = OperationGuard {
        app: Rc::downgrade(&app),
        token,
        stage: Stage::Signing,
        message: "Activity signing was interrupted. Preserve the reserved draft and reload before retrying.",
    };
    let mut request_token = [0; 16];
    request_token[..8].copy_from_slice(&token.generation.to_be_bytes());
    request_token[8..].copy_from_slice(&token.operation.to_be_bytes());
    let request = Array::new();
    request.push(&JsValue::from_str("sign-activity"));
    request.push(&Uint8Array::from(request_token.as_slice()));
    request.push(&Uint8Array::from(bytes.as_slice()));
    let sent = app
        .borrow()
        .worker
        .as_ref()
        .is_some_and(|worker| worker.post_message(&request).is_ok());
    if !sent {
        fail(
            &app,
            "Could not reach the identity worker. Preserve the reserved draft and reload.",
        );
    } else {
        status(
            &app,
            "Signing the exact reserved activity on this device…",
            false,
        );
        render(&app);
    }
    let result = receiver.await.unwrap_or_else(|_| Err(
        "Identity signing was interrupted. Preserve the reserved draft and reload before retrying.".into()
    ));
    drop(guard);
    result
}

fn finish_activity(app: &App, fields: &Array) {
    let data = (
        fields.get(1).dyn_into::<Uint8Array>(),
        fields.get(2).dyn_into::<Uint8Array>(),
        fields.get(3).dyn_into::<Uint8Array>(),
    );
    let (Ok(token), Ok(id), Ok(raw)) = data else {
        fail(
            app,
            "The signing worker returned invalid data. Preserve the reserved draft and reload.",
        );
        return;
    };
    if token.length() != 16 || id.length() != 32 || raw.length() as usize > MAX_EVENT_BYTES {
        fail(
            app,
            "The signing worker returned invalid data. Preserve the reserved draft and reload.",
        );
        return;
    }
    let token = token.to_vec();
    let token = Token {
        generation: u64::from_be_bytes(token[..8].try_into().unwrap()),
        operation: u64::from_be_bytes(token[8..].try_into().unwrap()),
    };
    // A valid but late response from a prior operation cannot resolve the new one.
    if !app.borrow().current(token, Stage::Signing) {
        return;
    }
    let draft = {
        let state = app.borrow();
        match &state.pending.as_ref().unwrap().kind {
            PendingKind::Activity { draft, .. } => draft.clone(),
            _ => {
                drop(state);
                fail(
                    app,
                    "The signing worker returned an unexpected response. Reload to retry.",
                );
                return;
            }
        }
    };
    let signed = SignedEvent::decode(&raw.to_vec());
    let Ok(signed) = signed else {
        fail(
            app,
            "The signing worker returned malformed activity. Preserve the draft and reload.",
        );
        return;
    };
    if signed.id() != draft.id()
        || id.to_vec().as_slice() != draft.id().as_bytes()
        || signed.unverified_claims() != draft.claims()
        || signed.clone().verify().is_err()
    {
        fail(
            app,
            "The signing worker response did not match the reserved activity. Reload before retrying.",
        );
        return;
    }
    let pending = app.borrow_mut().pending.take().unwrap();
    if let PendingKind::Activity { reply, .. } = pending.kind {
        let _ = reply.send(Ok(signed));
    }
    // Identity state was already unlocked; no asynchronous reply may unlock it.
    status(
        app,
        "Activity signed. See Room activity for local outbox and delivery status.",
        false,
    );
    render(app);
}

fn take_password(app: &App) -> Option<Zeroizing<String>> {
    let field = input(app, "password");
    let password = Zeroizing::new(field.value());
    field.set_value("");
    if !(MIN_PASSWORD_BYTES..=MAX_PASSWORD_BYTES).contains(&password.len()) {
        status(app, "Use a password between 12 and 1,024 bytes.", true);
        return None;
    }
    Some(password)
}
fn begin_operation(app: &App, stage: Stage, duration: f64) -> Option<Token> {
    let mut state = app.borrow_mut();
    if !state.can_operate() {
        return None;
    }
    let operation = state.operation.checked_add(1)?;
    state.operation = operation;
    let token = Token {
        generation: state.generation,
        operation,
    };
    state.pending = Some(Pending {
        token,
        stage,
        deadline: state.clock.now() + duration,
        cancel: Rc::new(Cancellation::default()),
        kind: PendingKind::Vault { created: false },
    });
    Some(token)
}
fn send_request(app: &App, token: Token, operation: &str, password: &str, raw: Option<&[u8]>) {
    if !app.borrow().current(token, Stage::Worker) {
        return;
    }
    let fields = Array::new();
    fields.push(&JsValue::from_str(operation));
    fields.push(&JsValue::from_str(password));
    if let Some(raw) = raw {
        fields.push(&Uint8Array::from(raw));
    }
    let sent = app
        .borrow()
        .worker
        .as_ref()
        .is_some_and(|w| w.post_message(&fields).is_ok());
    // Structured clone has completed; avoid retaining this additional JS copy.
    // Browser-managed input/event/string copies cannot be guaranteed zeroized.
    fields.set(1, JsValue::UNDEFINED);
    if sent {
        status(
            app,
            "Protecting your identity. This work stays on your device…",
            false,
        );
        render(app);
    } else {
        fail(app, "Could not reach the identity worker. Reload to retry.");
    }
}
fn request(app: &App, operation: &str, raw: Option<&[u8]>) {
    if !app.borrow().can_operate() {
        return;
    }
    let Some(password) = take_password(app) else {
        return;
    };
    let Some(token) = begin_operation(app, Stage::Worker, KDF_MS) else {
        return;
    };
    app.borrow_mut().pending.as_mut().unwrap().kind = PendingKind::Vault {
        created: operation == "create",
    };
    send_request(app, token, operation, &password, raw);
}
fn bind(app: &App, id: &str, kind: &str, mut callback: impl FnMut(&App, Event) + 'static) {
    let weak = Rc::downgrade(app);
    let handler = Closure::<dyn FnMut(Event)>::new(move |event| {
        if let Some(app) = weak.upgrade() {
            callback(&app, event);
        }
    });
    element(app, id)
        .add_event_listener_with_callback(kind, handler.as_ref().unchecked_ref())
        .expect("static listener");
    // Fixed one-time listeners, never added on render or user action.
    handler.forget();
}
fn download(app: &App) -> Result<(), JsValue> {
    let (document, raw) = {
        let state = app.borrow();
        if !state.can_operate() || state.downloads.len() >= MAX_DOWNLOADS {
            return Err(JsValue::NULL);
        }
        let raw = state
            .saved
            .vault()
            .and_then(|image| image.records().next())
            .ok_or(JsValue::NULL)?
            .to_vec();
        (state.document.clone(), raw)
    };
    let envelope = Envelope::from_bytes(&raw).map_err(|_| JsValue::NULL)?;
    let parts = Array::new();
    parts.push(&Uint8Array::from(raw.as_slice()));
    let blob = web_sys::Blob::new_with_u8_array_sequence(&parts)?;
    let link: HtmlAnchorElement = document.create_element("a")?.dyn_into()?;
    let body = document.body().ok_or(JsValue::NULL)?;
    let url = web_sys::Url::create_object_url_with_blob(&blob)?;
    link.set_href(&url);
    link.set_download(&format!(
        "vhalla-{}.vhkey",
        &hex(&envelope.claimed_public_key())[..12]
    ));
    let appended = link
        .set_attribute("hidden", "")
        .and_then(|()| body.append_child(&link).map(|_| ()));
    if let Err(error) = appended {
        let _ = web_sys::Url::revoke_object_url(&url);
        return Err(error);
    }
    link.click();
    link.remove();
    let mut state = app.borrow_mut();
    let deadline = state.clock.now() + 10_000.0;
    state.downloads.push((url, deadline));
    Ok(())
}
fn watchdog(app: &App) {
    let expired = {
        let mut state = app.borrow_mut();
        // This timer cannot run until an active worker callback has returned.
        state.retired.clear();
        let now = state.clock.now();
        state.downloads.retain(|(url, deadline)| {
            if now >= *deadline {
                let _ = web_sys::Url::revoke_object_url(url);
                false
            } else {
                true
            }
        });
        if state.failed {
            None
        } else if state
            .storage
            .as_ref()
            .is_some_and(IndexedStorage::needs_reopen)
        {
            Some(
                "Local storage changed or was interrupted. Identity locked; reload to reconcile saved state.",
            )
        } else if state.ready_deadline.is_some_and(|deadline| now >= deadline) {
            Some("The identity worker did not become ready. Reload to retry.")
        } else if state.load_deadline.is_some_and(|deadline| now >= deadline) {
            Some(
                "Local storage did not respond. Close older Valhalla tabs and reload; saved data has not been replaced.",
            )
        } else if state.pending.as_ref().is_some_and(|p| now >= p.deadline) {
            Some(
                "The identity operation timed out. Reload to reconcile saved state before retrying.",
            )
        } else {
            None
        }
    };
    if let Some(message) = expired {
        fail(app, message);
    }
}
pub fn start() {
    let Some(window) = web_sys::window() else {
        return;
    };
    let Some(document) = window.document() else {
        return;
    };
    let Some(clock) = window.performance() else {
        if let Some(status) = document.get_element_by_id("status") {
            status.set_text_content(Some(
                "Browser timing support is unavailable. Reload in a supported browser.",
            ));
        }
        return;
    };
    let load_cancel = Rc::new(Cancellation::default());
    let app = Rc::new(RefCell::new(State {
        #[cfg(feature = "private-rooms")]
        private: private::PrivateState::default(),
        document,
        clock,
        storage: None,
        saved: IdentitySnapshot::empty(),
        worker: None,
        callbacks: None,
        retired: Vec::new(),
        generation: 0,
        operation: 0,
        ready: false,
        unlocked: false,
        failed: false,
        loading: true,
        load_cancel: Some(load_cancel.clone()),
        load_deadline: None,
        ready_deadline: None,
        pending: None,
        downloads: Vec::new(),
    }));
    IDENTITY.with(|slot| *slot.borrow_mut() = Some(Rc::downgrade(&app)));
    let weak = Rc::downgrade(&app);
    let timer = Closure::<dyn FnMut()>::new(move || {
        if let Some(app) = weak.upgrade() {
            watchdog(&app);
        }
    });
    if window
        .set_interval_with_callback_and_timeout_and_arguments_0(timer.as_ref().unchecked_ref(), 500)
        .is_err()
    {
        fail(
            &app,
            "Browser timing support is unavailable. Reload to retry.",
        );
        return;
    }
    // Exactly one document-lifetime watchdog; no accumulating per-operation timers.
    timer.forget();
    bind(&app, "identity-form", "submit", |app, event| {
        event.prevent_default();
        if app.borrow().saved.vault().is_none() {
            request(app, "create", None);
        } else {
            let raw = app
                .borrow()
                .saved
                .vault()
                .and_then(|i| i.records().next().map(<[u8]>::to_vec));
            request(app, "unlock", raw.as_deref());
        }
    });
    bind(&app, "unlock", "click", |app, _| {
        let raw = app
            .borrow()
            .saved
            .vault()
            .and_then(|i| i.records().next().map(<[u8]>::to_vec));
        request(app, "unlock", raw.as_deref());
    });
    bind(&app, "lock", "click", |app, _| {
        if !app.borrow().can_operate_base() {
            return;
        }
        input(app, "password").set_value("");
        if start_worker(app).is_err() {
            fail(app, "Identity locked. Reload before unlocking again.");
        } else {
            status(
                app,
                "Identity locked. Your encrypted backup remains saved.",
                false,
            );
            render(app);
        }
    });
    bind(&app, "backup", "click", |app, _| {
        if !app.borrow().can_operate() {
            return;
        }
        if download(app).is_err() {
            status(
                app,
                "Could not request the encrypted backup download. Wait a moment and retry.",
                true,
            );
        } else {
            status(
                app,
                "Backup download requested for this tab's saved identity. Verify the file was saved, and keep its password separately.",
                false,
            );
        }
    });
    bind(&app, "restore", "click", |app, _| {
        if !app.borrow().can_operate() {
            return;
        }
        let file = input(app, "restore-file").files().and_then(|f| f.get(0));
        let Some(file) = file else {
            status(app, "Choose an encrypted .vhkey backup first.", true);
            return;
        };
        if file.size() != ENVELOPE_BYTES as f64 {
            status(
                app,
                "This file is not a supported encrypted identity backup.",
                true,
            );
            return;
        }
        // Capture the password before awaiting the file; never read a later edit.
        let Some(password) = take_password(app) else {
            return;
        };
        let Some(token) = begin_operation(app, Stage::ReadingFile, STORAGE_MS) else {
            return;
        };
        let cancel = app.borrow().pending.as_ref().unwrap().cancel.clone();
        status(app, "Reading the encrypted backup…", false);
        render(app);
        let app = app.clone();
        spawn_local(async move {
            let read = cancellable(cancel, JsFuture::from(file.array_buffer())).await;
            if !app.borrow().current(token, Stage::ReadingFile) {
                return;
            }
            let Some(Ok(buffer)) = read else {
                operation_error(
                    &app,
                    token,
                    Stage::ReadingFile,
                    "Could not read this backup file.",
                    false,
                );
                return;
            };
            let raw = Uint8Array::new(&buffer);
            if raw.length() as usize != ENVELOPE_BYTES {
                operation_error(
                    &app,
                    token,
                    Stage::ReadingFile,
                    "This file is not a supported encrypted identity backup.",
                    false,
                );
                return;
            }
            {
                let mut state = app.borrow_mut();
                let deadline = state.clock.now() + KDF_MS;
                let pending = state.pending.as_mut().unwrap();
                pending.stage = Stage::Worker;
                pending.deadline = deadline;
            }
            send_request(&app, token, "unlock", &password, Some(&raw.to_vec()));
        });
    });
    if start_worker(&app).is_err() {
        fail(
            &app,
            "Browser identity support is unavailable. Use an HTTPS origin and reload.",
        );
        std::mem::forget(app);
        return;
    }
    {
        let mut state = app.borrow_mut();
        state.load_deadline = Some(state.clock.now() + STORAGE_MS);
    }
    render(&app);
    spawn_local(async move {
        let result = cancellable(load_cancel, async {
            let mut storage = IndexedStorage::open(Namespace::new(PROFILE)).await?;
            let saved = storage.load_identity().await?;
            Ok::<_, vhalla_browser_storage::Error>((storage, saved))
        })
        .await;
        if !app.borrow().failed {
            if let Some(Ok((storage, saved))) = result {
                {
                    let mut state = app.borrow_mut();
                    state.storage = Some(storage);
                    state.saved = saved;
                    state.loading = false;
                    state.load_deadline = None;
                    state.load_cancel = None;
                }
                if app.borrow().ready {
                    status(
                        &app,
                        "Local workspace ready. Enter your password to unlock or create an identity.",
                        false,
                    );
                }
                render(&app);
            } else {
                fail(
                    &app,
                    "Saved state could not be read. Close older Valhalla tabs and reload; existing data has been preserved.",
                );
            }
        }
        // Keep this single application owner alive for the document lifetime.
        std::mem::forget(app);
    });
}
