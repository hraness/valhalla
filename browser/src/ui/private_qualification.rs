//! Synthetic loopback qualification of the actual UI broker and account worker.
//! Compiled only with BOTH private-rooms and local-qualification. No UI activation.
use super::*;
use crate::private_wire::{Bytes, Request, Response};
use serde_json::{json, Value};
use std::pin::Pin;
use vhalla_browser_storage::browser::private_rooms::IndexedPrivateStore;
use vhalla_private_kernel::{
    protocol::{Key, RoomId, Validity},
    storage::Store,
    Context, OperationId, OutboxKind,
};

thread_local! {
    static CANCEL: RefCell<Option<oneshot::Sender<()>>> = const { RefCell::new(None) };
}

fn allowed() -> Result<(), String> {
    let window = web_sys::window().ok_or("Window required")?;
    let origin = window.location().origin().map_err(|_| "origin")?;
    if origin != "http://127.0.0.1:8790" {
        return Err("qualification requires exact isolated loopback origin".into());
    }
    Ok(())
}
fn app() -> Result<App, String> {
    IDENTITY
        .with(|s| s.borrow().as_ref().and_then(Weak::upgrade))
        .ok_or("identity UI unavailable".into())
}
fn error(value: impl std::fmt::Debug) -> String {
    format!("qualification refusal: {value:?}")
}
fn ensure(condition: bool, message: &str) -> Result<(), String> {
    if condition {
        Ok(())
    } else {
        Err(message.into())
    }
}
fn bytes(raw: &[u8]) -> Bytes {
    Zeroizing::new(raw.to_vec())
}
fn op(n: u8) -> OperationId {
    OperationId::from_bytes([n; 16]).expect("fixed nonzero test operation")
}
fn validity(extra: u64) -> Result<Validity, String> {
    let seconds = js_sys::Date::now() / 1000.0;
    ensure(seconds.is_finite() && seconds >= 1.0, "invalid clock")?;
    let now = seconds as u64;
    Validity::new(now, now.checked_add(extra).ok_or("clock overflow")?).map_err(error)
}
fn locator(context: Context) -> Result<String, String> {
    Ok(hex(&Request::Open(context).encode().map_err(error)?))
}
fn selected(raw: &str) -> Result<Context, String> {
    // This is a qualification locator, not a new product backup format.
    ensure(
        raw.len() == (b"VHBRPRIVATE\x01".len() + 1 + 128) * 2,
        "locator width",
    )?;
    ensure(
        raw.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
        "locator alphabet",
    )?;
    let mut decoded = Vec::with_capacity(raw.len() / 2);
    for pair in raw.as_bytes().as_chunks::<2>().0 {
        let pair = std::str::from_utf8(pair).map_err(error)?;
        decoded.push(u8::from_str_radix(pair, 16).map_err(error)?);
    }
    match Request::decode(&decoded).map_err(error)? {
        Request::Open(context) => Ok(context),
        _ => Err("locator kind".into()),
    }
}
async fn image(context: Context) -> Result<Vec<u8>, String> {
    let mut store = IndexedPrivateStore::open(Namespace::new(PROFILE), context)
        .await
        .map_err(error)?;
    let image = store
        .load(context)
        .await
        .map_err(error)?
        .ok_or("missing image")?;
    Ok(image.as_bytes().to_vec())
}
async fn open(context: Context) -> Result<(), String> {
    private::enter().await?;
    let result = private::execute(Request::Open(context)).await?;
    ensure(
        matches!(result, Response::Membership(m) if m.status.context == context),
        "open scope",
    )
}
async fn cancelable(request: Request) -> Result<Response, String> {
    let (sender, mut canceled) = oneshot::channel();
    ensure(
        CANCEL.with(|s| s.borrow().is_none()),
        "qualification already active",
    )?;
    CANCEL.with(|s| *s.borrow_mut() = Some(sender));
    let mut task = Box::pin(private::execute(request));
    let result = poll_fn(|cx| {
        if Pin::new(&mut canceled).poll(cx).is_ready() {
            return Poll::Ready(None);
        }
        task.as_mut().poll(cx).map(Some)
    })
    .await;
    CANCEL.with(|s| {
        s.borrow_mut().take();
    });
    // The actual private broker's Drop guard must run, not a test replacement.
    drop(task);
    result.ok_or("synthetic caller canceled after held committed reply")?
}

/// Cancel only the one synthetic qualification caller, using its real Drop path.
#[wasm_bindgen]
pub fn qualify_private_cancel() -> Result<(), JsValue> {
    allowed().map_err(|e| JsValue::from_str(&e))?;
    let sender = CANCEL
        .with(|s| s.borrow_mut().take())
        .ok_or_else(|| JsValue::from_str("no pending qualification"))?;
    sender
        .send(())
        .map_err(|_| JsValue::from_str("qualification already finished"))
}

/// Fixed synthetic phases, exact loopback only. No raw key or generic signer.
#[wasm_bindgen]
pub async fn qualify_private_session(phase: String, retained: String) -> Result<String, JsValue> {
    async fn run(phase: &str, retained: &str) -> Result<Value, String> {
        allowed()?;
        match phase {
            "transport-snapshot" => {
                let app = app()?;
                let state = app.borrow();
                ensure(
                    state.can_operate() && state.unlocked,
                    "normal unlocked account required",
                )?;
                let vault = state
                    .saved
                    .vault()
                    .and_then(|v| v.records().next())
                    .ok_or("vault")?;
                let public = Envelope::from_bytes(vault)
                    .map_err(error)?
                    .claimed_public_key();
                let entry = Request::Enter {
                    vault: bytes(vault),
                    local_birth: state.saved.local_creation(public).is_ok(),
                }
                .encode()
                .map_err(error)?;
                Ok(json!({"vault":hex(vault),"entry":hex(&entry)}))
            }
            "prepare" => {
                private::enter().await?;
                let Response::Prepared(preview) =
                    private::execute(Request::PrepareOwner(validity(3600)?)).await?
                else {
                    return Err("prepare variant".into());
                };
                let token = locator(preview.context)?;
                ensure(
                    private::retained_locator() == Some(preview.context),
                    "prepared locator lost",
                )?;
                Ok(json!({"locator":token}))
            }
            "commit" => {
                let context = selected(retained)?;
                // Harness has written this exact locator to a new file first.
                private::acknowledge_retained_locator(context)?;
                let Response::Membership(view) =
                    private::execute(Request::CommitCreation(context)).await?
                else {
                    return Err("commit variant".into());
                };
                ensure(
                    view.status.context == context && view.status.outbox_head == 0,
                    "new store status",
                )?;
                Ok(json!({"committed":true,"epoch":view.status.epoch}))
            }
            "send-for-cancel" => {
                let context = selected(retained)?;
                let Response::Draft(consent) = private::execute(Request::PrepareMessage(bytes(
                    b"SYNTHETIC PRIVATE LOCAL QUALIFICATION",
                )))
                .await?
                else {
                    return Err("draft variant".into());
                };
                ensure(consent.context == context, "draft scope")?;
                ensure(
                    cancelable(Request::Send {
                        operation: op(11),
                        consent,
                    })
                    .await
                    .is_err(),
                    "canceled result released",
                )?;
                let app = app()?;
                ensure(
                    app.borrow().failed && !app.borrow().unlocked && app.borrow().worker.is_none(),
                    "cancel retained worker authority",
                )?;
                ensure(
                    private::retained_locator() == Some(context),
                    "cancel lost exact locator",
                )?;
                Ok(json!({"canceled":true,"locked":true}))
            }
            "reopen" => {
                let context = selected(retained)?;
                open(context).await?;
                let Response::Outbox { head, records, .. } = private::execute(Request::Outbox {
                    after: 0,
                    limit: 16,
                })
                .await?
                else {
                    return Err("outbox variant".into());
                };
                ensure(
                    head == 1 && records.len() == 1,
                    "committed canceled operation missing",
                )?;
                let artifact = records.into_iter().next().ok_or("missing artifact")?;
                ensure(
                    artifact.sequence == 1
                        && artifact.operation == op(11)
                        && artifact.kind == OutboxKind::Application,
                    "retained operation differs",
                )?;
                let same = Response::Artifact { context, artifact }
                    .encode()
                    .map_err(error)?;
                Ok(json!({"retained_reply":hex(&same)}))
            }
            "stale-consent" => {
                let context = selected(retained)?;
                let Response::Draft(consent) = private::execute(Request::PrepareMessage(bytes(
                    b"NEVER MOVE THIS OLD EPOCH DRAFT",
                )))
                .await?
                else {
                    return Err("draft variant".into());
                };
                let epoch = consent.epoch;
                private::execute(Request::Renew {
                    operation: op(12),
                    validity: validity(7200)?,
                })
                .await?;
                let accepted = image(context).await?;
                ensure(
                    private::execute(Request::Send {
                        operation: op(13),
                        consent,
                    })
                    .await
                    .is_err(),
                    "old consent accepted",
                )?;
                ensure(
                    image(context).await? == accepted,
                    "stale draft changed state",
                )?;
                ensure(app()?.borrow().failed, "stale draft failure did not lock")?;
                Ok(json!({"stale_refused":true,"old_epoch":epoch}))
            }
            "verify-renewal" => {
                let context = selected(retained)?;
                open(context).await?;
                let Response::Membership(view) = private::execute(Request::Membership).await?
                else {
                    return Err("membership variant".into());
                };
                ensure(
                    view.status.outbox_head == 2 && view.status.control_sequence == 1,
                    "renewal or refused-send floor",
                )?;
                Ok(json!({"epoch":view.status.epoch,"outbox":view.status.outbox_head}))
            }
            "replace-vault" => {
                let context = selected(retained)?;
                let accepted = image(context).await?;
                let app = app()?;
                let original = app.borrow().saved.clone();
                let raw = original
                    .vault()
                    .and_then(|v| v.records().next())
                    .ok_or("vault")?;
                let mut changed = raw.to_vec();
                *changed.last_mut().ok_or("empty vault")? ^= 1;
                // Structurally valid same-key ciphertext replacement, never used
                // as key authority; exact pair CAS and normal strict durability.
                let changed = Image::new(Slot::Vault, &[&changed]).map_err(error)?;
                let mut profile = IndexedStorage::open(Namespace::new(PROFILE))
                    .await
                    .map_err(error)?;
                let replaced = profile
                    .replace_identity(&original, &changed)
                    .await
                    .map_err(error)?;
                let refused = private::execute(Request::Membership).await.is_err();
                // Restore only our exact synthetic predecessor for later cases.
                profile
                    .replace_identity(&replaced, original.vault().ok_or("original vault")?)
                    .await
                    .map_err(error)?;
                ensure(
                    refused && app.borrow().failed && !app.borrow().unlocked,
                    "replaced vault retained authority",
                )?;
                ensure(
                    image(context).await? == accepted,
                    "vault refusal modified private room",
                )?;
                Ok(json!({"replaced_vault_refused":true,"image_unchanged":true}))
            }
            "wrong-account" => {
                let context = selected(retained)?;
                let accepted = image(context).await?;
                private::enter().await?;
                let mut encoded = [0x66; 32];
                encoded[0] = 0x58;
                let other = Key::from_bytes(encoded).map_err(error)?;
                ensure(other != context.account, "synthetic account collision")?;
                let before = private::retained_locator();
                ensure(
                    private::execute(Request::Open(Context {
                        account: other,
                        ..context
                    }))
                    .await
                    .is_err(),
                    "foreign account accepted",
                )?;
                ensure(
                    private::retained_locator() == before && image(context).await? == accepted,
                    "foreign account changed locator/state",
                )?;
                private::execute(Request::Open(context)).await?;
                Ok(json!({"wrong_account_refused":true}))
            }
            "missing-state" => {
                let context = selected(retained)?;
                private::enter().await?;
                let mut room = *context.scope.room.as_bytes();
                room[0] ^= 0x40;
                let absent = Context {
                    scope: vhalla_private_kernel::protocol::PrivateRoomScope {
                        room: RoomId::from_bytes(room).map_err(error)?,
                        ..context.scope
                    },
                    ..context
                };
                ensure(
                    private::execute(Request::Open(absent)).await.is_err(),
                    "missing room initialized",
                )?;
                ensure(
                    app()?.borrow().failed && private::retained_locator() == Some(absent),
                    "missing room did not require exact reopen",
                )?;
                ensure(
                    IndexedPrivateStore::open(Namespace::new(PROFILE), absent)
                        .await
                        .is_err(),
                    "missing room was created",
                )?;
                Ok(json!({"missing_refused":true}))
            }
            "leave" => {
                private::leave_and_lock()?;
                let app = app()?;
                ensure(
                    !app.borrow().unlocked && !app.borrow().private.active,
                    "leave retained authority",
                )?;
                ensure(
                    private::execute(Request::Membership).await.is_err(),
                    "new worker implicitly reopened",
                )?;
                Ok(json!({"locked":true}))
            }
            _ => Err("unknown fixed qualification phase".into()),
        }
    }
    run(&phase, &retained)
        .await
        .map(|v| v.to_string())
        .map_err(|e| JsValue::from_str(&e))
}
