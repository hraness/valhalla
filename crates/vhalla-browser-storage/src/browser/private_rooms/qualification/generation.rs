//! Real IndexedDB pause/cutover transactions over fresh synthetic custody.
use super::*;
use crate::browser::private_delivery::{DeliveryWrite, IndexedDelivery};
use crate::private_rooms::DeliveryGeneration;
use vhalla_private_kernel::protocol::RoomId;

pub(super) async fn run(
    namespace: Namespace,
    mut context: Context,
    hook: &Function,
) -> Result<(), JsValue> {
    context.scope.room = RoomId::from_bytes([201; 32]).map_err(fail)?;
    let first = image(1);
    let second = image(2);
    let selected = DeliveryGeneration {
        generation: 0,
        binding: [1; 32],
        namespace: [2; 32],
        paused: true,
        transition: [3; 32],
    };
    let mut kernel = IndexedPrivateStore::create_new(namespace, context, Limits::default())
        .await
        .map_err(fail)?;
    kernel
        .publish(context, None, &first, &[])
        .await
        .map_err(fail)?;
    let mut delivery = IndexedDelivery::open(namespace, context)
        .await
        .map_err(fail)?;
    delivery
        .publish(DeliveryWrite {
            expected: None,
            next: b"live",
            retain: Some((1, b"old ciphertext")),
            discard: None,
        })
        .await
        .map_err(fail)?;

    // A kernel transaction admitted before pause must finish first. The pause's
    // exact image comparison then refuses without publishing a false receipt.
    let mut mutation = Box::pin(kernel.publish(context, Some(&first), &second, &[]));
    start_once(mutation.as_mut())?;
    ensure(
        delivery
            .pause(b"live", b"paused", &first, selected, b"receipt")
            .await
            .is_err(),
        "pause ignored earlier kernel publication",
    )?;
    mutation.await.map_err(fail)?;
    drop(delivery);
    delivery = IndexedDelivery::open(namespace, context)
        .await
        .map_err(fail)?;
    ensure(
        delivery.generation().is_none()
            && delivery.load().await.map_err(fail)?.as_deref() == Some(b"live"),
        "failed pause changed selection",
    )?;

    for mode in [
        "deny-writes",
        "ignored-options",
        "throw-durability",
        "abort-write",
    ] {
        control(hook, mode)?;
        ensure(
            delivery
                .pause(b"live", b"paused", &second, selected, b"receipt")
                .await
                .is_err(),
            "faulted pause succeeded",
        )?;
        control(hook, "require-strict")?;
        drop(delivery);
        delivery = IndexedDelivery::open(namespace, context)
            .await
            .map_err(fail)?;
        ensure(
            delivery.generation().is_none()
                && delivery.load().await.map_err(fail)?.as_deref() == Some(b"live"),
            "faulted pause escaped atomicity",
        )?;
    }
    let mut canceled = Box::pin(delivery.pause(b"live", b"paused", &second, selected, b"receipt"));
    start_once(canceled.as_mut())?;
    drop(canceled);
    drop(delivery);
    delivery = IndexedDelivery::open(namespace, context)
        .await
        .map_err(fail)?;
    ensure(
        delivery.generation().is_none(),
        "canceled pause escaped atomicity",
    )?;

    let mut stale = IndexedDelivery::open(namespace, context)
        .await
        .map_err(fail)?;
    delivery
        .pause(b"live", b"paused", &second, selected, b"receipt")
        .await
        .map_err(fail)?;
    ensure(
        stale.load().await.is_err(),
        "stale delivery read survived pause",
    )?;
    ensure(
        kernel
            .publish(context, Some(&second), &image(3), &[])
            .await
            .is_err(),
        "old kernel handle wrote after pause",
    )?;
    drop(kernel);
    drop(delivery);
    kernel = IndexedPrivateStore::open(namespace, context)
        .await
        .map_err(fail)?;
    ensure(
        kernel.load(context).await.map_err(fail)? == Some(second.clone()),
        "paused history changed",
    )?;
    ensure(
        kernel
            .publish(context, Some(&second), &image(3), &[])
            .await
            .is_err(),
        "reopened paused kernel wrote",
    )?;
    delivery = IndexedDelivery::open(namespace, context)
        .await
        .map_err(fail)?;
    ensure(
        delivery.pause_receipt().await.map_err(fail)?.as_deref() == Some(b"receipt"),
        "pause receipt lost on reopen",
    )?;
    ensure(
        delivery.load_retained(1).await.map_err(fail)?.as_deref() == Some(b"old ciphertext"),
        "paused retained ciphertext changed",
    )?;
    for mode in [
        "deny-writes",
        "ignored-options",
        "throw-durability",
        "abort-write",
    ] {
        control(hook, mode)?;
        ensure(
            delivery.publish_paused(b"paused", b"intent").await.is_err(),
            "faulted successor intent succeeded",
        )?;
        control(hook, "require-strict")?;
        drop(delivery);
        delivery = IndexedDelivery::open(namespace, context)
            .await
            .map_err(fail)?;
        ensure(
            delivery.generation() == Some(selected)
                && delivery.load().await.map_err(fail)?.as_deref() == Some(b"paused")
                && delivery.pause_receipt().await.map_err(fail)?.as_deref() == Some(b"receipt"),
            "faulted successor intent changed paused evidence",
        )?;
    }
    let mut canceled = Box::pin(delivery.publish_paused(b"paused", b"intent"));
    start_once(canceled.as_mut())?;
    drop(canceled);
    drop(delivery);
    delivery = IndexedDelivery::open(namespace, context)
        .await
        .map_err(fail)?;
    ensure(
        delivery.load().await.map_err(fail)?.as_deref() == Some(b"paused"),
        "canceled successor intent escaped atomicity",
    )?;
    delivery
        .publish_paused(b"paused", b"intent")
        .await
        .map_err(fail)?;
    let successor = DeliveryGeneration {
        generation: 1,
        binding: [4; 32],
        namespace: [5; 32],
        paused: false,
        ..selected
    };
    for mode in [
        "deny-writes",
        "ignored-options",
        "throw-durability",
        "abort-write",
    ] {
        control(hook, mode)?;
        ensure(
            delivery
                .select_successor(b"intent", b"successor", successor)
                .await
                .is_err(),
            "faulted successor succeeded",
        )?;
        control(hook, "require-strict")?;
        drop(delivery);
        delivery = IndexedDelivery::open(namespace, context)
            .await
            .map_err(fail)?;
        ensure(
            delivery.generation() == Some(selected)
                && delivery.load().await.map_err(fail)?.as_deref() == Some(b"intent"),
            "faulted successor changed selection",
        )?;
    }
    let mut canceled = Box::pin(delivery.select_successor(b"intent", b"successor", successor));
    start_once(canceled.as_mut())?;
    drop(canceled);
    drop(delivery);
    delivery = IndexedDelivery::open(namespace, context)
        .await
        .map_err(fail)?;
    ensure(
        delivery.generation() == Some(selected),
        "canceled successor changed selection",
    )?;
    let mut stale = IndexedDelivery::open(namespace, context)
        .await
        .map_err(fail)?;
    delivery
        .select_successor(b"intent", b"successor", successor)
        .await
        .map_err(fail)?;
    drop(delivery);
    delivery = IndexedDelivery::open(namespace, context)
        .await
        .map_err(fail)?;
    ensure(
        delivery.generation() == Some(successor),
        "committed successor lost across reopen",
    )?;
    ensure(
        stale.load_retained(1).await.is_err(),
        "predecessor handle aliased successor",
    )?;
    ensure(
        delivery.load_retained(1).await.map_err(fail)?.is_none(),
        "predecessor position leaked into successor",
    )?;
    delivery
        .publish(DeliveryWrite {
            expected: Some(b"successor"),
            next: b"after",
            retain: Some((1, b"new ciphertext")),
            discard: None,
        })
        .await
        .map_err(fail)?;
    ensure(
        delivery.load_retained(1).await.map_err(fail)?.as_deref() == Some(b"new ciphertext"),
        "successor ciphertext missing",
    )?;
    drop(kernel);
    kernel = IndexedPrivateStore::open(namespace, context)
        .await
        .map_err(fail)?;
    ensure(
        kernel.load(context).await.map_err(fail)? == Some(second.clone()),
        "cutover rewrote kernel image",
    )?;
    kernel
        .publish(context, Some(&second), &image(3), &[])
        .await
        .map_err(fail)?;
    let keys = [
        format!(
            "{}delivery-v1/retained/00000000000000000001",
            model::prefix(context)
        ),
        format!(
            "{}delivery-generations-v1/00/archive",
            model::prefix(context)
        ),
    ];
    let old = raw_values(&mut kernel.inner, &keys).await?;
    ensure(
        old == [Some(b"old ciphertext".to_vec()), Some(b"intent".to_vec())],
        "cutover changed predecessor archive or ciphertext",
    )?;
    Ok(())
}
