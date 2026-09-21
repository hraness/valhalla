use crate::fixture::{ensure, fail, Fixture};
use js_sys::Function;
use sha2::{Digest, Sha256};
use std::{
    future::Future,
    task::{Context, Poll, Waker},
};
use vhalla_browser_storage::{
    browser::outbox::{continuity_qualification as raw, IndexedOutbox},
    outbox::{
        continuity::{Limits, SessionScope, Snapshot},
        AuthorScope,
    },
    Error, Namespace, PublishError,
};
use vhalla_public_protocol::continuity as wire;
use wasm_bindgen::JsValue;

fn control(hook: &Function, mode: &str) -> Result<(), JsValue> {
    hook.call1(&JsValue::NULL, &mode.into()).map(|_| ())
}
fn start_once(future: std::pin::Pin<&mut impl Future>) -> Result<(), JsValue> {
    ensure(
        matches!(
            future.poll(&mut Context::from_waker(Waker::noop())),
            Poll::Pending
        ),
        "expected real asynchronous IndexedDB boundary",
    )
}
async fn open(namespace: Namespace) -> Result<IndexedOutbox, JsValue> {
    IndexedOutbox::open(namespace).await.map_err(fail)
}
async fn load(outbox: &mut IndexedOutbox, f: &Fixture) -> Result<Snapshot, JsValue> {
    outbox
        .load_continuity(f.scope.clone(), f.limits)
        .await
        .map_err(fail)
}
async fn attempt(
    outbox: &mut IndexedOutbox,
    state: &Snapshot,
    request: wire::Request,
    body: &[u8],
) -> Result<Snapshot, JsValue> {
    outbox
        .publish_continuity(state.prepare_attempt(request, body).map_err(fail)?)
        .await
        .map_err(fail)
}
async fn answer(
    outbox: &mut IndexedOutbox,
    state: &Snapshot,
    proof: &wire::ResponseProof,
    body: &[u8],
) -> Result<Snapshot, JsValue> {
    outbox
        .publish_continuity(state.prepare_response(proof, body).map_err(fail)?)
        .await
        .map_err(fail)
}

/// All authority/cryptographic inputs are deterministic synthetic fixtures.
/// Only IndexedDB atomicity, strict completion and retained binding are qualified.
pub async fn run(namespace: Namespace, hook: Function) -> Result<String, JsValue> {
    control(&hook, "require-strict")?;
    let f = Fixture::new(33)?;
    let mut outbox = f.initialize(namespace).await?;
    let source = raw::source_image(&mut outbox, &f.scope, 33)
        .await
        .map_err(fail)?;
    let state = Box::pin(roles_and_reopen(namespace, &f, &mut outbox)).await?;
    drop(outbox);
    Box::pin(stale_and_proof_refusals(namespace, &f, state)).await?;
    Box::pin(transaction_faults(namespace, &f, &hook)).await?;
    Box::pin(cancellation(namespace, &f)).await?;
    Box::pin(capacity_and_missing(namespace, &f, &hook)).await?;
    let mut outbox = open(namespace).await?;
    ensure(
        raw::source_image(&mut outbox, &f.scope, 33)
            .await
            .map_err(fail)?
            == source,
        "continuity changed v1 author/history/delivery bytes",
    )?;
    let delivery = outbox
        .load_delivery(f.scope.author(), f.scope.peer())
        .await
        .map_err(fail)?
        .ok_or_else(|| fail("v1 delivery missing"))?;
    ensure(
        delivery.sequence() == 1,
        "continuity advanced v1 delivery floor",
    )?;
    drop(outbox);
    // Each damaged case retains its own task-owned namespace, without repair.
    for mode in [1u8, 2] {
        let mut id = *namespace.identifier();
        id[31] ^= mode;
        Box::pin(source_mutation(Namespace::new(id), mode)).await?;
    }
    control(&hook, "finish")?;
    Ok("real strict IndexedDB continuity receipts: Stage/Status hints and terminal separated from exact two-page retention; reopen and original proofs; nonce/scope/signature/generation/source refusals; abort/durability/quota faults; cancellation before and after actual commit; fixed quotas; missing-prefix refusal; v1 bytes unchanged".into())
}

async fn roles_and_reopen(
    namespace: Namespace,
    f: &Fixture,
    outbox: &mut IndexedOutbox,
) -> Result<Snapshot, JsValue> {
    let mut state = f.select(outbox, f.scope.clone(), f.limits).await?;
    let request = f.status(&state, 1)?;
    state = attempt(outbox, &state, request, &[]).await?;
    let (proof, body) = f.status_reply(request)?;
    state = answer(outbox, &state, &proof, &body).await?;
    ensure(
        state.retention().position() == wire::Position::EMPTY && state.terminal().is_none(),
        "Status falsely acknowledged a prefix",
    )?;

    let body = wire::Body::stage(f.events[..32].to_vec()).map_err(fail)?;
    let encoded = body.encode();
    let request = wire::Request::stage(
        f.context(2),
        f.scope.author().author(),
        wire::Position::EMPTY,
        None,
        &body,
    )
    .map_err(fail)?;
    state = attempt(outbox, &state, request, &encoded).await?;
    // Reopen sees the exact body that a controller may now submit, not a proof.
    let mut reopened = open(namespace).await?;
    let saved = load(&mut reopened, f).await?;
    ensure(
        saved == state
            && saved
                .attempt()
                .is_some_and(|a| a.body() == encoded && a.request() == request),
        "reopen lost exact durable Stage attempt",
    )?;
    drop(reopened);
    let ticket = wire::StageRef::new(
        [4; 32],
        wire::Position::EMPTY,
        wire::Position::of(&f.events[31]),
        1,
        2000,
    )
    .map_err(fail)?;
    let (proof, raw) = f.proof(
        request,
        wire::Reply::Staged(wire::StageAck {
            observed: f.context(2).floor,
            base: wire::Position::EMPTY,
            ticket,
            submitted_end: wire::Position::of(&f.events[31]),
            submitted_body: Sha256::digest(&encoded).into(),
        }),
    )?;
    state = answer(outbox, &state, &proof, &raw).await?;
    ensure(
        state.retention().position() == wire::Position::EMPTY && state.terminal().is_none(),
        "Stage ticket falsely acknowledged a prefix",
    )?;

    let body = wire::Body::commit(Vec::new(), f.terminal().clone()).map_err(fail)?;
    let request = wire::Request::commit(
        f.context(3),
        f.scope.author().author(),
        wire::Position::EMPTY,
        Some(ticket),
        &body,
    )
    .map_err(fail)?;
    state = attempt(outbox, &state, request, &body.encode()).await?;
    let (terminal_proof, terminal_body) = f.proof(
        request,
        wire::Reply::Committed(Box::new(wire::TerminalReceipt {
            observed: f.context(3).floor,
            event: f.terminal().clone(),
            cursor: 7,
            registry: [9; 32],
            reconciled: true,
        })),
    )?;
    state = answer(outbox, &state, &terminal_proof, &terminal_body).await?;
    ensure(
        state.terminal().is_some()
            && !state.complete()
            && state.retention().position() == wire::Position::EMPTY,
        "terminal proof falsely acknowledged historical retention",
    )?;
    let terminal = state.terminal();

    let request = wire::Request::new(
        f.context(4),
        wire::Selection::Author(f.scope.author().author()),
        wire::Kind::Evidence {
            after: wire::Position::EMPTY,
            count: 32,
        },
    )
    .map_err(fail)?;
    state = attempt(outbox, &state, request, &[]).await?;
    let (first_proof, first_body) = f.evidence(request, 0, 32)?;
    state = answer(outbox, &state, &first_proof, &first_body).await?;
    ensure(
        state.retention().position() == wire::Position::of(&f.events[31]) && !state.complete(),
        "partial Evidence page completed job",
    )?;
    let mut reopened = open(namespace).await?;
    ensure(
        load(&mut reopened, f).await? == state,
        "partial prefix changed on reopen",
    )?;
    drop(reopened);
    let request = wire::Request::new(
        f.context(5),
        wire::Selection::Author(f.scope.author().author()),
        wire::Kind::Evidence {
            after: state.retention().position(),
            count: 1,
        },
    )
    .map_err(fail)?;
    state = attempt(outbox, &state, request, &[]).await?;
    let (proof, body) = f.evidence(request, 32, 33)?;
    state = answer(outbox, &state, &proof, &body).await?;
    ensure(
        state.complete() && state.terminal() == terminal && state.record_count() == 5,
        "exact Evidence suffix did not complete selected terminal",
    )?;
    let physical = raw::receipt_image(outbox, &f.scope, 5)
        .await
        .map_err(fail)?;
    let mut reopened = open(namespace).await?;
    ensure(
        load(&mut reopened, f).await? == state
            && raw::receipt_image(&mut reopened, &f.scope, 5)
                .await
                .map_err(fail)?
                == physical,
        "receipt bytes changed on connection reopen",
    )?;
    for (index, proof, body) in [
        (3, terminal_proof, terminal_body),
        (4, first_proof, first_body),
    ] {
        let record = reopened
            .continuity_record(f.scope.clone(), f.limits, index)
            .await
            .map_err(fail)?
            .ok_or_else(|| fail("original proof missing"))?;
        ensure(
            record.proof().encode() == proof.encode() && record.body() == body,
            "original signed reply was replaced with metadata",
        )?;
    }
    Ok(state)
}

async fn stale_and_proof_refusals(
    namespace: Namespace,
    f: &Fixture,
    state: Snapshot,
) -> Result<(), JsValue> {
    let mut outbox = open(namespace).await?;
    let old_request = f.status(&state, 6)?;
    let old = attempt(&mut outbox, &state, old_request, &[]).await?;
    let (old_proof, old_body) = f.status_reply(old_request)?;
    let stale_candidate = old.prepare_response(&old_proof, &old_body).map_err(fail)?;
    let request = f.status(&old, 7)?;
    let current = attempt(&mut outbox, &old, request, &[]).await?;
    let bytes = raw::receipt_image(&mut outbox, &f.scope, 6)
        .await
        .map_err(fail)?;
    ensure(
        current.prepare_response(&old_proof, &old_body).is_err(),
        "late nonce proof admitted",
    )?;
    ensure(
        current.prepare_attempt(request, &[]).is_err(),
        "immediate request nonce reused",
    )?;
    let (proof, body) = f.status_reply(request)?;
    let mut damaged = proof.encode();
    *damaged.last_mut().unwrap() ^= 1;
    let damaged = wire::ResponseProof::decode(&damaged).map_err(fail)?;
    ensure(
        current.prepare_response(&damaged, &body).is_err(),
        "invalid peer signature admitted",
    )?;
    let mut foreign = request.context();
    foreign.scope.room[0] ^= 1;
    let foreign = wire::Request::new(foreign, request.selection(), request.kind()).map_err(fail)?;
    let (foreign_proof, foreign_body) = f.status_reply(foreign)?;
    ensure(
        current
            .prepare_response(&foreign_proof, &foreign_body)
            .is_err(),
        "foreign room proof admitted",
    )?;
    ensure(
        matches!(
            outbox.publish_continuity(stale_candidate).await,
            Err(PublishError::ReopenRequired(Error::Stale))
        ),
        "old generation published after a new durable attempt",
    )?;
    ensure(outbox.needs_reopen(), "failed CAS did not latch")?;
    drop(outbox);
    let mut outbox = open(namespace).await?;
    ensure(
        load(&mut outbox, f).await? == current
            && raw::receipt_image(&mut outbox, &f.scope, 6)
                .await
                .map_err(fail)?
                == bytes,
        "failed nonce/generation checks changed receipt state",
    )?;
    let next = answer(&mut outbox, &current, &proof, &body).await?;
    ensure(
        next.record_count() == 6,
        "current exact response not retained once",
    )
}

async fn transaction_faults(
    namespace: Namespace,
    f: &Fixture,
    hook: &Function,
) -> Result<(), JsValue> {
    let mut outbox = open(namespace).await?;
    let state = load(&mut outbox, f).await?;
    let request = f.status(&state, 8)?;
    let state = attempt(&mut outbox, &state, request, &[]).await?;
    let (proof, body) = f.status_reply(request)?;
    let bytes = raw::receipt_image(&mut outbox, &f.scope, 7)
        .await
        .map_err(fail)?;
    for mode in [
        "deny-writes",
        "ignored-options",
        "throw-durability",
        "abort-write",
    ] {
        control(hook, mode)?;
        let candidate = state.prepare_response(&proof, &body).map_err(fail)?;
        ensure(
            outbox.publish_continuity(candidate).await.is_err(),
            "injected strict transaction failure acknowledged",
        )?;
        ensure(
            outbox.needs_reopen(),
            "failed transaction kept handle usable",
        )?;
        if mode != "abort-write" {
            control(hook, "assert-no-mutation")?;
        }
        control(hook, "require-strict")?;
        drop(outbox);
        outbox = open(namespace).await?;
        ensure(
            load(&mut outbox, f).await? == state
                && raw::receipt_image(&mut outbox, &f.scope, 7)
                    .await
                    .map_err(fail)?
                    == bytes,
            "failed strict publication leaked a record/head",
        )?;
    }
    let state = answer(&mut outbox, &state, &proof, &body).await?;
    ensure(
        state.record_count() == 7,
        "failed transaction retry duplicated receipt",
    )?;
    control(hook, "deny-writes")?;
    ensure(
        load(&mut outbox, f).await? == state,
        "readonly receipt load changed state",
    )?;
    control(hook, "assert-no-write")?;
    control(hook, "require-strict")
}

async fn cancellation(namespace: Namespace, f: &Fixture) -> Result<(), JsValue> {
    let mut outbox = open(namespace).await?;
    let state = load(&mut outbox, f).await?;
    let request = f.status(&state, 9)?;
    let state = attempt(&mut outbox, &state, request, &[]).await?;
    let (proof, body) = f.status_reply(request)?;
    let before = raw::receipt_image(&mut outbox, &f.scope, 8)
        .await
        .map_err(fail)?;
    let mut pending =
        Box::pin(outbox.publish_continuity(state.prepare_response(&proof, &body).map_err(fail)?));
    start_once(pending.as_mut())?;
    drop(pending); // Actual transaction guard aborts; not a fake backend error.
    ensure(
        outbox.needs_reopen(),
        "cancel before completion left handle usable",
    )?;
    drop(outbox);
    let mut outbox = open(namespace).await?;
    ensure(
        load(&mut outbox, f).await? == state
            && raw::receipt_image(&mut outbox, &f.scope, 8)
                .await
                .map_err(fail)?
                == before,
        "canceled transaction left a partial receipt",
    )?;
    let state = answer(&mut outbox, &state, &proof, &body).await?;
    ensure(
        state.record_count() == 8,
        "canceled exact retry not retained once",
    )?;

    let request = f.status(&state, 10)?;
    let state = attempt(&mut outbox, &state, request, &[]).await?;
    let (proof, body) = f.status_reply(request)?;
    let candidate = state.prepare_response(&proof, &body).map_err(fail)?;
    let projected = candidate.projected().clone(); // Nondurable until observer checks below.
    let mut observer = open(namespace).await?;
    let mut pending = Box::pin(outbox.publish_continuity(candidate));
    start_once(pending.as_mut())?;
    // The later readonly transaction is ordered after this actual readwrite tx.
    // It proves commit happened before canceling the still-unpolled caller future.
    let committed = load(&mut observer, f).await?;
    ensure(
        committed == projected && committed.record_count() == 9,
        "commit-before-cancel was not observed",
    )?;
    drop(pending);
    ensure(
        outbox.needs_reopen(),
        "lost completion kept publisher ready",
    )?;
    drop(outbox);
    drop(observer);
    let mut outbox = open(namespace).await?;
    let recovered = load(&mut outbox, f).await?;
    ensure(
        recovered == committed && recovered.attempt().is_none(),
        "uncertain committed result did not reconcile",
    )?;
    let retained = outbox
        .continuity_record(f.scope.clone(), f.limits, 9)
        .await
        .map_err(fail)?
        .ok_or_else(|| fail("lost committed receipt"))?;
    ensure(
        retained.proof().encode() == proof.encode() && retained.body() == body,
        "uncertain result replaced original proof",
    )?;
    // A stale retry is refused atomically; recovery returns the original record.
    let before = raw::receipt_image(&mut outbox, &f.scope, 9)
        .await
        .map_err(fail)?;
    ensure(
        outbox
            .publish_continuity(state.prepare_response(&proof, &body).map_err(fail)?)
            .await
            .is_err(),
        "uncertain retry wrote a second record",
    )?;
    drop(outbox);
    let mut outbox = open(namespace).await?;
    ensure(
        load(&mut outbox, f).await? == recovered
            && raw::receipt_image(&mut outbox, &f.scope, 9)
                .await
                .map_err(fail)?
                == before,
        "uncertain exact retry changed retained result",
    )
}

async fn capacity_and_missing(
    namespace: Namespace,
    f: &Fixture,
    hook: &Function,
) -> Result<(), JsValue> {
    let mut outbox = open(namespace).await?;
    for (host, limits) in [
        (
            "record-quota",
            Limits {
                max_records: 1,
                max_bytes: 4 * 1024 * 1024,
            },
        ),
        (
            "byte-quota",
            Limits {
                max_records: 12,
                max_bytes: 1,
            },
        ),
    ] {
        let scope = f.route(host)?;
        let mut state = f.select(&mut outbox, scope.clone(), limits).await?;
        let request = f.status(&state, 20)?;
        state = attempt(&mut outbox, &state, request, &[]).await?;
        let (proof, body) = f.status_reply(request)?;
        if limits.max_records == 1 {
            state = answer(&mut outbox, &state, &proof, &body).await?;
            let request = f.status(&state, 21)?;
            state = attempt(&mut outbox, &state, request, &[]).await?;
        }
        let request = state.attempt().unwrap().request();
        let (proof, body) = f.status_reply(request)?;
        let bytes = raw::receipt_image(&mut outbox, &scope, 2)
            .await
            .map_err(fail)?;
        ensure(
            matches!(state.prepare_response(&proof, &body), Err(Error::Bounds)),
            "fixed receipt quota exceeded",
        )?;
        ensure(
            raw::receipt_image(&mut outbox, &scope, 2)
                .await
                .map_err(fail)?
                == bytes,
            "quota refusal changed receipt bytes",
        )?;
        let wrong = Limits {
            max_records: limits.max_records + 1,
            ..limits
        };
        ensure(
            outbox.load_continuity(scope.clone(), wrong).await == Err(Error::WrongScope),
            "reopen silently changed immutable quota",
        )?;
        drop(outbox);
        outbox = open(namespace).await?;
        ensure(
            outbox
                .load_continuity(scope.clone(), limits)
                .await
                .map_err(fail)?
                == state,
            "fixed quota did not survive reopen",
        )?;
        ensure(
            outbox
                .create_continuity(scope.clone(), wrong)
                .await
                .is_err(),
            "create reset existing quota",
        )?;
        drop(outbox);
        outbox = open(namespace).await?;
        ensure(
            raw::receipt_image(&mut outbox, &scope, 2)
                .await
                .map_err(fail)?
                == bytes,
            "quota reset refusal changed bytes",
        )?;
    }
    let absent = f.route("never-created")?;
    control(hook, "deny-writes")?;
    ensure(
        outbox.load_continuity(absent.clone(), f.limits).await == Err(Error::RecoveryRequired),
        "missing session inferred fresh",
    )?;
    control(hook, "assert-no-write")?;
    control(hook, "require-strict")?;
    drop(outbox);
    outbox = open(namespace).await?;
    ensure(
        raw::receipt_image(&mut outbox, &absent, 0)
            .await
            .map_err(fail)?
            .iter()
            .all(Option::is_none),
        "missing session load created prefix",
    )?;

    let other_key = ed25519_dalek::SigningKey::from_bytes(&[11; 32])
        .verifying_key()
        .to_bytes();
    let missing_author = AuthorScope::new(f.events[0].claims().scope, other_key);
    let scope = SessionScope::new(
        missing_author,
        f.scope.history(),
        f.scope.peer(),
        f.scope.endpoint().clone(),
    )
    .map_err(fail)?;
    ensure(
        outbox
            .load_head(missing_author)
            .await
            .map_err(fail)?
            .is_none(),
        "foreign author unexpectedly exists",
    )?;
    ensure(
        outbox
            .create_continuity(scope.clone(), f.limits)
            .await
            .is_err(),
        "receipt session fabricated an author",
    )?;
    drop(outbox);
    outbox = open(namespace).await?;
    ensure(
        outbox
            .load_head(missing_author)
            .await
            .map_err(fail)?
            .is_none()
            && raw::receipt_image(&mut outbox, &scope, 0)
                .await
                .map_err(fail)?
                .iter()
                .all(Option::is_none),
        "failed receipt creation wrote an author or prefix",
    )?;

    let scope = f.route("lost-format")?;
    let state = f.select(&mut outbox, scope.clone(), f.limits).await?;
    raw::damage(&mut outbox, &scope, raw::Damage::MissingReceiptFormat)
        .await
        .map_err(fail)?;
    let bytes = raw::receipt_image(&mut outbox, &scope, 0)
        .await
        .map_err(fail)?;
    ensure(
        outbox.load_continuity(scope.clone(), f.limits).await == Err(Error::RecoveryRequired),
        "lost FORMAT inferred fresh",
    )?;
    drop(outbox);
    outbox = open(namespace).await?;
    ensure(
        outbox
            .create_continuity(scope.clone(), f.limits)
            .await
            .is_err(),
        "create overwrote surviving STATE",
    )?;
    drop(outbox);
    outbox = open(namespace).await?;
    ensure(
        raw::receipt_image(&mut outbox, &scope, 0)
            .await
            .map_err(fail)?
            == bytes
            && bytes[1].as_deref() == Some(state.encode().as_slice()),
        "missing FORMAT evidence was repaired or replaced",
    )
}

async fn source_mutation(namespace: Namespace, mode: u8) -> Result<(), JsValue> {
    let f = Fixture::new(1)?;
    let mut outbox = f.initialize(namespace).await?;
    let state = f.select(&mut outbox, f.scope.clone(), f.limits).await?;
    let request = f.status(&state, 1)?;
    let state = attempt(&mut outbox, &state, request, &[]).await?;
    let (proof, body) = f.status_reply(request)?;
    let candidate = state.prepare_response(&proof, &body).map_err(fail)?;
    let fault = if mode == 1 {
        let mut claims = f.events[0].claims().clone();
        claims.content = vhalla_room_activity::Content::Text(
            vhalla_room_activity::Text::new("different valid signed bytes").map_err(fail)?,
        );
        let event = vhalla_room_activity::UnsignedEvent::new(claims)
            .map_err(fail)?
            .sign_with_key(&ed25519_dalek::SigningKey::from_bytes(&[3; 32]))
            .map_err(fail)?
            .verify()
            .map_err(fail)?;
        raw::Damage::FirstSourceFrame(event.encode())
    } else {
        raw::Damage::MissingAuthorHead
    };
    raw::damage(&mut outbox, &f.scope, fault)
        .await
        .map_err(fail)?;
    let source = raw::source_image(&mut outbox, &f.scope, 1)
        .await
        .map_err(fail)?;
    let receipts = raw::receipt_image(&mut outbox, &f.scope, 1)
        .await
        .map_err(fail)?;
    ensure(
        outbox.publish_continuity(candidate).await.is_err(),
        "source changed after preparation but receipt committed",
    )?;
    ensure(outbox.needs_reopen(), "source failure did not latch")?;
    drop(outbox);
    let mut outbox = open(namespace).await?;
    ensure(
        raw::source_image(&mut outbox, &f.scope, 1)
            .await
            .map_err(fail)?
            == source
            && raw::receipt_image(&mut outbox, &f.scope, 1)
                .await
                .map_err(fail)?
                == receipts,
        "source refusal changed evidence or receipt state",
    )?;
    ensure(
        outbox
            .load_continuity(f.scope.clone(), f.limits)
            .await
            .is_err(),
        "reopen trusted missing/changed source",
    )
}
