//! Synthetic Window/worker fixture only, excluded unless qualification is enabled.
use super::*;
use js_sys::Function;
use std::{
    future::Future,
    task::{Context as TaskContext, Poll, Waker},
};
use vhalla_private_kernel::OperationId;

fn fail(error: impl std::fmt::Debug) -> JsValue {
    JsValue::from_str(&format!("private storage qualification: {error:?}"))
}
fn ensure(test: bool, message: &str) -> Result<(), JsValue> {
    if test {
        Ok(())
    } else {
        Err(fail(message))
    }
}
fn image(value: u8) -> Image {
    Image::from_bytes(&[value; 40]).expect("bounded synthetic image")
}
fn record(key: RecordKey, value: u8) -> StoredRecord {
    StoredRecord::from_bytes(key, &[value; 80]).expect("bounded synthetic record")
}
fn control(hook: &Function, mode: &str) -> Result<(), JsValue> {
    hook.call1(&JsValue::NULL, &mode.into()).map(|_| ())
}
fn start_once(future: std::pin::Pin<&mut impl Future>) -> Result<(), JsValue> {
    ensure(
        matches!(
            future.poll(&mut TaskContext::from_waker(Waker::noop())),
            Poll::Pending
        ),
        "expected asynchronous IndexedDB boundary",
    )
}
async fn tamper(
    store: &mut IndexedPrivateStore,
    key: String,
    value: Option<Vec<u8>>,
) -> Result<(), JsValue> {
    store
        .run(true, move |tx| {
            if let Some(value) = value {
                tx.put(&key, &value)?;
            } else {
                tx.store
                    .delete(&key.into())
                    .map_err(super::super::storage)?;
            }
            *tx.result.borrow_mut() = Some(Ok(()));
            Ok(())
        })
        .await
        .map_err(fail)
}

/// Exercise only fresh synthetic namespaces. The hook injects browser storage
/// failures, never a domain callback during a publication transaction.
pub async fn run(
    namespace: Namespace,
    contexts: [Context; 8],
    hook: Function,
) -> Result<String, JsValue> {
    control(&hook, "require-strict")?;
    let ctx = contexts[0];
    let limits = Limits {
        max_records: 6,
        max_record_bytes: 480,
    };
    ensure(
        matches!(
            IndexedPrivateStore::open(namespace, ctx).await,
            Err(StoreError::Corrupt)
        ),
        "missing FORMAT opened as fresh",
    )?;
    let mut store = IndexedPrivateStore::create_new(namespace, ctx, limits)
        .await
        .map_err(fail)?;
    ensure(
        store.load(ctx).await.map_err(fail)?.is_none(),
        "initial scope not pristine",
    )?;
    ensure(
        IndexedPrivateStore::create_new(namespace, ctx, limits)
            .await
            .is_err(),
        "second create reset custody",
    )?;
    ensure(
        matches!(store.load(contexts[1]).await, Err(StoreError::Refused)),
        "foreign context admitted",
    )?;
    let first = image(1);
    let next = image(2);
    let event = record(RecordKey::Outbox(1), 3);
    let index = record(
        RecordKey::Operation(OperationId::from_bytes([7; 16]).map_err(fail)?),
        4,
    );
    let control_record = record(RecordKey::Control(1), 5);
    ensure(
        RecordKey::Control(0).validate().is_err(),
        "zero control sequence accepted",
    )?;
    store
        .publish(
            ctx,
            None,
            &first,
            &[control_record.clone(), event.clone(), index.clone()],
        )
        .await
        .map_err(fail)?;
    ensure(
        store
            .read(ctx, control_record.key())
            .await
            .map_err(fail)?
            .as_ref()
            .map(StoredRecord::as_bytes)
            == Some(control_record.as_bytes()),
        "atomic control record missing",
    )?;
    ensure(
        store
            .read(ctx, index.key())
            .await
            .map_err(fail)?
            .as_ref()
            .map(StoredRecord::as_bytes)
            == Some(index.as_bytes()),
        "atomic operation record missing",
    )?;
    ensure(
        store
            .read(ctx, RecordKey::Outbox(2))
            .await
            .map_err(fail)?
            .is_none(),
        "never-published key falsely present",
    )?;

    // Start A before B; transaction-local CAS permits only A's exact transition.
    let mut other = IndexedPrivateStore::open(namespace, ctx)
        .await
        .map_err(fail)?;
    let mut pending = Box::pin(store.publish(ctx, Some(&first), &next, &[]));
    start_once(pending.as_mut())?;
    ensure(
        matches!(
            other.publish(ctx, Some(&first), &image(9), &[]).await,
            Err(StoreError::Conflict)
        ),
        "stale competing tab won CAS",
    )?;
    pending.await.map_err(fail)?;
    drop(other);
    drop(store);
    let mut store = IndexedPrivateStore::open(namespace, ctx)
        .await
        .map_err(fail)?;
    ensure(
        store
            .load(ctx)
            .await
            .map_err(fail)?
            .as_ref()
            .map(Image::as_bytes)
            == Some(next.as_bytes()),
        "reopen lost exact current image",
    )?;
    // Preflight all three immutable records: an earlier new key cannot escape a later collision.
    ensure(
        matches!(
            store
                .publish(
                    ctx,
                    Some(&next),
                    &image(8),
                    &[
                        record(RecordKey::Control(2), 5),
                        record(RecordKey::Outbox(2), 5),
                        record(index.key(), 6)
                    ]
                )
                .await,
            Err(StoreError::Conflict)
        ),
        "immutable collision accepted",
    )?;
    drop(store);
    let mut store = IndexedPrivateStore::open(namespace, ctx)
        .await
        .map_err(fail)?;
    ensure(
        store
            .read(ctx, RecordKey::Outbox(2))
            .await
            .map_err(fail)?
            .is_none(),
        "partial record escaped conflict",
    )?;

    ensure(
        matches!(
            store
                .publish(
                    ctx,
                    Some(&next),
                    &image(8),
                    &[
                        record(RecordKey::Control(2), 5),
                        record(RecordKey::Outbox(2), 5),
                        index.clone()
                    ]
                )
                .await,
            Err(StoreError::Conflict)
        ),
        "equal third immutable collision advanced image",
    )?;
    drop(store);
    let mut store = IndexedPrivateStore::open(namespace, ctx)
        .await
        .map_err(fail)?;
    ensure(
        store
            .load(ctx)
            .await
            .map_err(fail)?
            .as_ref()
            .map(Image::as_bytes)
            == Some(next.as_bytes()),
        "equal collision changed state",
    )?;

    for mode in [
        "deny-writes",
        "ignored-options",
        "throw-durability",
        "abort-write",
    ] {
        control(&hook, mode)?;
        ensure(
            store
                .publish(ctx, Some(&next), &image(7), &[])
                .await
                .is_err(),
            "synthetic write fault accepted",
        )?;
        ensure(store.needs_reopen(), "uncertain write did not latch")?;
        control(&hook, "require-strict")?;
        drop(store);
        store = IndexedPrivateStore::open(namespace, ctx)
            .await
            .map_err(fail)?;
        ensure(
            store
                .load(ctx)
                .await
                .map_err(fail)?
                .as_ref()
                .map(Image::as_bytes)
                == Some(next.as_bytes()),
            "failed write changed state",
        )?;
    }
    let canceled_next = image(6);
    let mut canceled = Box::pin(store.publish(ctx, Some(&next), &canceled_next, &[]));
    start_once(canceled.as_mut())?;
    drop(canceled);
    ensure(store.needs_reopen(), "canceled write left handle usable")?;
    drop(store);
    let mut store = IndexedPrivateStore::open(namespace, ctx)
        .await
        .map_err(fail)?;
    ensure(
        store
            .load(ctx)
            .await
            .map_err(fail)?
            .as_ref()
            .map(Image::as_bytes)
            == Some(next.as_bytes()),
        "canceled write escaped atomic abort",
    )?;
    let mut canceled = Box::pin(store.load(ctx));
    start_once(canceled.as_mut())?;
    drop(canceled);
    ensure(store.needs_reopen(), "canceled read left handle usable")?;
    drop(store);

    let mut check = IndexedPrivateStore::open(namespace, ctx)
        .await
        .map_err(fail)?;
    ensure(
        check
            .read(ctx, RecordKey::Control(2))
            .await
            .map_err(fail)?
            .is_none(),
        "control record escaped collision",
    )?;
    drop(check);

    // Each corruption case has a separate preserved scope; never reset evidence.
    for (ctx, missing_data) in [(contexts[1], true), (contexts[2], false)] {
        let mut store = IndexedPrivateStore::create_new(namespace, ctx, limits)
            .await
            .map_err(fail)?;
        store
            .publish(ctx, None, &first, std::slice::from_ref(&event))
            .await
            .map_err(fail)?;
        let (data, proof) = model::record_keys(ctx, event.key()).map_err(fail)?;
        tamper(&mut store, if missing_data { data } else { proof }, None).await?;
        ensure(
            matches!(store.read(ctx, event.key()).await, Err(StoreError::Corrupt)),
            "missing publication half became None",
        )?;
        drop(store);
        let mut reopened = IndexedPrivateStore::open(namespace, ctx)
            .await
            .map_err(fail)?;
        ensure(
            matches!(
                reopened.read(ctx, event.key()).await,
                Err(StoreError::Corrupt)
            ),
            "missing half lost across reopen",
        )?;
    }
    for (ctx, suffix) in [
        (contexts[3], "record/010000000000000001"),
        (contexts[4], "published/010000000000000001"),
        (contexts[5], "\u{ffff}"),
    ] {
        let mut store = IndexedPrivateStore::create_new(namespace, ctx, limits)
            .await
            .map_err(fail)?;
        tamper(
            &mut store,
            format!("{}{suffix}", model::prefix(ctx)),
            Some(vec![3; 40]),
        )
        .await?;
        ensure(
            matches!(store.load(ctx).await, Err(StoreError::Corrupt)),
            "orphan prefix became pristine",
        )?;
        drop(store);
        ensure(
            matches!(
                IndexedPrivateStore::open(namespace, ctx).await,
                Err(StoreError::Corrupt)
            ),
            "open accepted orphaned prefix",
        )?;
        ensure(
            IndexedPrivateStore::create_new(namespace, ctx, limits)
                .await
                .is_err(),
            "create reset orphaned prefix",
        )?;
    }
    let ctx = contexts[6];
    let mut store = IndexedPrivateStore::create_new(
        namespace,
        ctx,
        Limits {
            max_records: 1,
            max_record_bytes: 80,
        },
    )
    .await
    .map_err(fail)?;
    store
        .publish(ctx, None, &first, std::slice::from_ref(&event))
        .await
        .map_err(fail)?;
    ensure(
        matches!(
            store
                .publish(ctx, Some(&first), &next, std::slice::from_ref(&index))
                .await,
            Err(StoreError::Refused)
        ),
        "capacity exceeded",
    )?;
    drop(store);
    let mut store = IndexedPrivateStore::open(namespace, ctx)
        .await
        .map_err(fail)?;
    ensure(
        store.read(ctx, index.key()).await.map_err(fail)?.is_none(),
        "capacity refusal published record",
    )?;
    drop(store);
    let ctx = contexts[7];
    let mut store = IndexedPrivateStore::create_new(namespace, ctx, limits)
        .await
        .map_err(fail)?;
    let maximum = Image::from_bytes(&vec![1; MAX_IMAGE_BYTES]).map_err(fail)?;
    store
        .publish(ctx, None, &maximum, std::slice::from_ref(&event))
        .await
        .map_err(fail)?;
    ensure(
        store
            .load(ctx)
            .await
            .map_err(fail)?
            .as_ref()
            .map(|image| image.as_bytes().len())
            == Some(MAX_IMAGE_BYTES),
        "maximum healthy image failed",
    )?;
    let (data, _) = model::record_keys(ctx, event.key()).map_err(fail)?;
    tamper(&mut store, data, Some(vec![1; MAX_STORED_RECORD_BYTES + 1])).await?;
    ensure(
        matches!(store.read(ctx, event.key()).await, Err(StoreError::Corrupt)),
        "oversized stored blob accepted",
    )?;
    control(&hook, "finish")?;
    Ok("private IndexedDB exact CAS, strict completion, stale tabs, cancellation, markers, orphan keys and bounded refusal passed".into())
}
