//! Closed negative archive scenarios, compiled only in the optional fixture.
//! Each caller supplies a fresh synthetic namespace; no generic mutation API.
use super::*;
use vhalla_private_kernel::{recovery::ArchiveExport, storage::ArchiveStore, StorageKey};

/// Remove only the first fixture outbox payload while retaining its publication
/// marker/accounting, then prove actual archive enumeration refuses completion.
/// This preserves the damaged fixture for inspection and does not reset it.
pub async fn missing_record_refuses_export(
    namespace: Namespace,
    context: Context,
    key: &StorageKey,
) -> Result<(), JsValue> {
    let mut store = IndexedPrivateStore::open(namespace, context)
        .await
        .map_err(fail)?;
    let before = store.accounting(context).await.map_err(fail)?;
    ensure(before.records > 0, "missing-record scenario lacks history")?;
    let (data, _) = model::record_keys(context, RecordKey::Outbox(1)).map_err(fail)?;
    tamper(&mut store, data, None).await?;
    drop(store);
    let store = IndexedPrivateStore::open(namespace, context)
        .await
        .map_err(fail)?;
    let mut export = ArchiveExport::open(store, key, context)
        .await
        .map_err(fail)?;
    let mut refused = false;
    for _ in 0..24 {
        match export.next_page().await {
            Err(_) => {
                refused = true;
                break;
            }
            Ok(Some(_)) => (),
            Ok(None) => return Err(fail("missing record produced complete archive")),
        }
    }
    ensure(
        refused && export.needs_reopen(),
        "missing record did not poison archive export",
    )?;
    drop(export);
    let mut check = IndexedPrivateStore::open(namespace, context)
        .await
        .map_err(fail)?;
    let after = check.accounting(context).await.map_err(fail)?;
    ensure(
        before.image == after.image
            && before.records == after.records
            && before.bytes == after.bytes,
        "missing-record refusal rewrote accounting",
    )?;
    ensure(
        matches!(
            check.read(context, RecordKey::Outbox(1)).await,
            Err(StoreError::Corrupt)
        ),
        "missing publication became absence",
    )
}

/// Add one actual indexed encrypted-record slot without changing this fixture's
/// authenticated source image. Correct accounting now exposes an extra record;
/// export must reject before claiming any complete source.
pub async fn extra_record_refuses_export(
    namespace: Namespace,
    context: Context,
    key: &StorageKey,
) -> Result<(), JsValue> {
    let mut store = IndexedPrivateStore::open(namespace, context)
        .await
        .map_err(fail)?;
    let before = store.accounting(context).await.map_err(fail)?;
    let image = before
        .image
        .as_ref()
        .ok_or_else(|| fail("source image absent"))?;
    let extra = record(
        RecordKey::Operation(OperationId::from_bytes([239; 16]).map_err(fail)?),
        13,
    );
    store
        .publish(context, Some(image), image, &[extra])
        .await
        .map_err(fail)?;
    let altered = store.accounting(context).await.map_err(fail)?;
    ensure(
        altered.records == before.records + 1 && altered.bytes == before.bytes + 80,
        "extra record did not cross real IDB commit",
    )?;
    drop(store);
    let store = IndexedPrivateStore::open(namespace, context)
        .await
        .map_err(fail)?;
    ensure(
        matches!(
            ArchiveExport::open(store, key, context).await,
            Err(vhalla_private_kernel::Error::Conflict)
        ),
        "extra record accepted as complete source",
    )?;
    let mut check = IndexedPrivateStore::open(namespace, context)
        .await
        .map_err(fail)?;
    let retained = check.accounting(context).await.map_err(fail)?;
    ensure(
        retained.image == altered.image
            && retained.records == altered.records
            && retained.bytes == altered.bytes,
        "extra-record refusal changed retained evidence",
    )
}
