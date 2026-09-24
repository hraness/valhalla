//! Trusted Rust UI broker. No private content is assigned to a public composer.
use super::*;
pub use crate::private_wire::{types::*, Request, Response};
use vhalla_private_kernel::Context;

const PRIVATE_MS: f64 = 120_000.0;
#[derive(Default)]
pub(super) struct PrivateState {
    pub active: bool,
    selected: Option<Context>,
    prepared: Option<Context>,
    acknowledged: Option<Context>,
    // Read-only archive context bound by an explicit import/open request.
    archive: Option<Context>,
    // Nonsecret recovery hint only, retained across worker failure/termination.
    locator: Option<Context>,
}
impl PrivateState {
    pub fn stopped(&mut self) {
        self.active = false;
        self.selected = None;
        self.prepared = None;
        self.acknowledged = None;
        self.archive = None;
    }
}
pub(super) struct Expected {
    kind: ReplyKind,
    account: [u8; 32],
    context: Option<Context>,
    body: Option<Bytes>,
    operation: Option<vhalla_private_kernel::OperationId>,
    artifact_kind: Option<vhalla_private_kernel::OutboxKind>,
}
struct PrivateGuard {
    app: Weak<RefCell<State>>,
    generation: u64,
    completed: bool,
}
impl Drop for PrivateGuard {
    fn drop(&mut self) {
        if self.completed {
            return;
        }
        if let Some(app) = self.app.upgrade() {
            let live = {
                let state = app.borrow();
                state.generation == self.generation && state.private.active
            };
            if live {
                // Covers cancellation after reply queueing but before caller
                // observation; a cleared Pending cannot restore authority.
                fail(&app, "Private operation canceled. Preserve the exact locator, reload and reopen it; never replace missing state.");
            }
        }
    }
}
fn app() -> Result<App, String> {
    IDENTITY
        .with(|slot| slot.borrow().as_ref().and_then(Weak::upgrade))
        .ok_or("Identity support is not ready.".into())
}

/// Enter irreversible private custody in this unlocked account worker. Public
/// signing/export remains disabled until a new worker is explicitly unlocked.
pub async fn enter() -> Result<(), String> {
    let app = app()?;
    let (vault, birth) = {
        let state = app.borrow();
        if !state.can_operate() || !state.unlocked || state.private.active {
            return Err("Unlock the saved identity and finish its current operation first.".into());
        }
        let raw = state
            .saved
            .vault()
            .and_then(|image| image.records().next())
            .ok_or("No saved identity.")?;
        let public = Envelope::from_bytes(raw)
            .map_err(|_| "Invalid saved identity.")?
            .claimed_public_key();
        (
            Zeroizing::new(raw.to_vec()),
            state.saved.local_creation(public).is_ok(),
        )
    };
    // Set before the request can await or post. A missing/taken worker key never
    // becomes an implicit permission to use the public broker.
    app.borrow_mut().private.active = true;
    request(
        &app,
        Request::Enter {
            vault,
            local_birth: birth,
        },
    )
    .await
    .map(|_| ())
}

/// Retain/export the exact preparation locator before calling this method.
/// This acknowledges trusted-UI retention; it is not proof a download finished.
/// Missing state at this locator must never be replaced with another creation.
pub fn acknowledge_retained_locator(context: Context) -> Result<(), String> {
    let app = app()?;
    let mut state = app.borrow_mut();
    if !state.can_operate_base() || !state.private.active || state.private.prepared != Some(context)
    {
        return Err("This locator is not the current prepared creation.".into());
    }
    state.private.locator = Some(context);
    state.private.acknowledged = Some(context);
    Ok(())
}
/// Unauthenticated recovery hint only. Exact open still authenticates the store.
pub fn retained_locator() -> Option<Context> {
    app().ok().and_then(|app| {
        let locator = app.borrow().private.locator;
        locator
    })
}

/// Execute one closed operation in the selected private worker. The returned
/// reports are for a trusted private UI, never automatic public/network export.
pub async fn execute(operation: Request) -> Result<Response, String> {
    if matches!(operation, Request::Enter { .. }) {
        return Err("Use explicit private entry.".into());
    }
    let app = app()?;
    request(&app, operation).await
}

/// Terminate both custodians and start a new locked worker. The caller must clear
/// its own private views/copies; no returned plaintext can be retracted. This API
/// never moves a private draft into the public composer or implicitly unlocks.
pub fn leave_and_lock() -> Result<(), String> {
    let app = app()?;
    let canceled = {
        let mut state = app.borrow_mut();
        if state.failed {
            return Err("Reload and retain the exact room locator before reopening.".into());
        }
        if !state.private.active {
            return Err("This worker is not in private mode.".into());
        }
        state.pending.take().map(|p| p.cancel)
    };
    if let Some(cancel) = canceled {
        cancel.cancel();
    }
    input(&app, "password").set_value("");
    if start_worker(&app).is_err() {
        fail(
            &app,
            "Private custody was locked. Reload before unlocking again.",
        );
        return Err("Could not start a new locked worker.".into());
    }
    status(
        &app,
        "Private custody locked. Explicitly unlock before choosing a new session.",
        false,
    );
    render(&app);
    Ok(())
}

async fn request(app: &App, operation: Request) -> Result<Response, String> {
    let raw = operation
        .encode()
        .map_err(|_| "Invalid or oversized private request.")?;
    let expected = {
        let mut state = app.borrow_mut();
        if !state.can_operate_base() || !state.unlocked || !state.private.active {
            return Err(
                "Private custody is unavailable or busy; explicitly reopen its exact locator."
                    .into(),
            );
        }
        let account = state
            .saved
            .vault()
            .and_then(|image| image.records().next())
            .and_then(|raw| Envelope::from_bytes(raw).ok())
            .ok_or("No authenticated saved identity.")?
            .claimed_public_key();
        let context = match &operation {
            Request::Enter { .. } => None,
            Request::PrepareOwner(_) | Request::PrepareContact { .. } => {
                if state.private.selected.is_some() || state.private.prepared.is_some() {
                    return Err("Lock and explicitly unlock a new worker before choosing another private room.".into());
                }
                None
            }
            Request::CommitCreation(context) => {
                if state.private.prepared != Some(*context)
                    || state.private.acknowledged != Some(*context)
                {
                    return Err(
                        "Retain the exact prepared locator before committing creation.".into(),
                    );
                }
                Some(*context)
            }
            Request::Open(context) => {
                if state.private.selected.is_some() || state.private.prepared.is_some() {
                    return Err("Lock and explicitly unlock a new worker before opening another private room.".into());
                }
                Some(*context)
            }
            Request::ArchiveImportBegin { context, .. } | Request::ArchiveOpen { context, .. } => {
                if state.private.selected.is_some() || state.private.prepared.is_some() {
                    return Err(
                        "Lock and explicitly unlock a new worker before archive work.".into(),
                    );
                }
                state.private.archive = Some(*context);
                Some(*context)
            }
            Request::ArchiveImportFeed(_)
            | Request::ArchiveImportFinish(_)
            | Request::ArchiveInspect
            | Request::ArchiveInbox { .. }
            | Request::ArchiveOutbox { .. }
            | Request::ArchiveClose => Some(
                state
                    .private
                    .archive
                    .ok_or("Begin an explicit archive import or open first.")?,
            ),
            _ => Some(
                state
                    .private
                    .selected
                    .ok_or("Open the exact private room first.")?,
            ),
        };
        if context.is_some_and(|c| c.account.as_bytes() != &account) {
            return Err("This room belongs to another account.".into());
        }
        if matches!(operation, Request::Open(_) | Request::CommitCreation(_)) {
            state.private.locator = context;
        }
        let (expected_operation, artifact_kind) = match &operation {
            Request::Send { operation, .. } => (
                Some(*operation),
                Some(vhalla_private_kernel::OutboxKind::Application),
            ),
            Request::Offer { operation, .. } => (Some(*operation), None),
            Request::ContactRequest { operation, .. } => (
                Some(*operation),
                Some(vhalla_private_kernel::OutboxKind::ContactRequest),
            ),
            Request::Accept { operation, .. } | Request::ConfirmAdmission { operation, .. } => (
                Some(*operation),
                Some(vhalla_private_kernel::OutboxKind::ContactInvitation),
            ),
            Request::Remove { operation, .. } => (
                Some(*operation),
                Some(vhalla_private_kernel::OutboxKind::Removal),
            ),
            Request::Renew { operation, .. } => (
                Some(*operation),
                Some(vhalla_private_kernel::OutboxKind::OwnerUpdate),
            ),
            Request::Succeed { operation, .. } => (
                Some(*operation),
                Some(vhalla_private_kernel::OutboxKind::Succession),
            ),
            _ => (None, None),
        };
        Expected {
            kind: operation.reply_kind(),
            account,
            context,
            body: if let Request::PrepareMessage(body) = &operation {
                Some(Zeroizing::new(body.to_vec()))
            } else {
                None
            },
            operation: expected_operation,
            artifact_kind,
        }
    };
    let token = {
        let mut state = app.borrow_mut();
        let number = state
            .operation
            .checked_add(1)
            .ok_or("Worker operation counter exhausted.")?;
        state.operation = number;
        Token {
            generation: state.generation,
            operation: number,
        }
    };
    let (sender, receiver) = oneshot::channel();
    {
        let mut state = app.borrow_mut();
        state.pending = Some(Pending {
            token,
            stage: Stage::Private,
            deadline: state.clock.now() + PRIVATE_MS,
            cancel: Rc::new(Cancellation::default()),
            kind: PendingKind::Private {
                expected,
                reply: sender,
            },
        });
    }
    let mut guard = PrivateGuard {
        app: Rc::downgrade(app),
        generation: token.generation,
        completed: false,
    };
    let mut token_bytes = [0; 16];
    token_bytes[..8].copy_from_slice(&token.generation.to_be_bytes());
    token_bytes[8..].copy_from_slice(&token.operation.to_be_bytes());
    let call = Array::new();
    call.push(&"private".into());
    call.push(&Uint8Array::from(token_bytes.as_slice()));
    let payload = Uint8Array::from(raw.as_slice());
    call.push(&payload);
    // Transfer the payload's ArrayBuffer: structured clone moves it to the
    // worker instead of copying it, and detaches this thread's JS-heap copy.
    let transfer = Array::of1(&payload.buffer());
    let sent = app
        .borrow()
        .worker
        .as_ref()
        .is_some_and(|worker| worker.post_message_with_transfer(&call, &transfer).is_ok());
    if !sent {
        fail(
            app,
            "Private worker unavailable. Preserve the exact locator and reopen after reload.",
        );
    } else {
        status(app, "Working inside private custody…", false);
        render(app);
    }
    let result = receiver.await.unwrap_or_else(|_| {
        Err("Private custody interrupted; reopen the exact retained locator.".into())
    });
    guard.completed = true;
    result
}

pub(super) fn finish(app: &App, fields: &Array) {
    let token = fields.get(1).dyn_into::<Uint8Array>();
    let raw = fields.get(2).dyn_into::<Uint8Array>();
    let (Ok(token), Ok(raw)) = (token, raw) else {
        fail(
            app,
            "Invalid private worker reply; reload to reconcile custody.",
        );
        return;
    };
    if token.length() != 16 || raw.length() as usize > MAX_FRAME {
        fail(app, "Private worker reply exceeds its bound.");
        return;
    }
    let token = token.to_vec();
    let token = Token {
        generation: u64::from_be_bytes(token[..8].try_into().unwrap()),
        operation: u64::from_be_bytes(token[8..].try_into().unwrap()),
    };
    if !app.borrow().current(token, Stage::Private) {
        return;
    }
    let decoded = Response::decode(&Zeroizing::new(raw.to_vec()));
    let Ok(response) = decoded else {
        fail(
            app,
            "Invalid private worker result; preserve the locator and reload.",
        );
        return;
    };
    let valid = {
        let state = app.borrow();
        if let Some(Pending {
            kind: PendingKind::Private { expected, .. },
            ..
        }) = state.pending.as_ref()
        {
            state.private.active
                && response.kind() == expected.kind
                && response
                    .context()
                    .is_none_or(|c| c.account.as_bytes() == &expected.account)
                && expected
                    .context
                    .is_none_or(|c| response.context() == Some(c))
                && match &response {
                    Response::Entered(key) => key.as_bytes() == &expected.account,
                    Response::Draft(consent) => expected
                        .body
                        .as_ref()
                        .is_some_and(|body| body.as_slice() == consent.body.as_slice()),
                    Response::Artifact { artifact, .. } => {
                        expected.operation == Some(artifact.operation)
                            && expected.artifact_kind == Some(artifact.kind)
                    }
                    Response::Offer { operation, .. } => expected.operation == Some(*operation),
                    _ => true,
                }
        } else {
            false
        }
    };
    if !valid {
        fail(
            app,
            "Private worker result did not match the selected operation and scope.",
        );
        return;
    }
    let pending = {
        let mut state = app.borrow_mut();
        match &response {
            Response::Prepared(preview) => {
                state.private.prepared = Some(preview.context);
                state.private.acknowledged = None;
                state.private.locator = Some(preview.context);
            }
            Response::Membership(view) => {
                state.private.selected = Some(view.status.context);
                state.private.prepared = None;
                state.private.acknowledged = None;
            }
            Response::ArchiveClosed { .. } => {
                state.private.archive = None;
            }
            _ => (),
        }
        state.pending.take().unwrap()
    };
    if let PendingKind::Private { reply, .. } = pending.kind {
        if reply.send(Ok(response)).is_err() {
            fail(app, "Private result was not retained by its caller. Preserve the exact locator and reopen after reload.");
            return;
        }
    }
    status(
        app,
        "Private operation complete locally. No artifact was sent to a network.",
        false,
    );
    render(app);
}
