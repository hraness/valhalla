//! Synthetic browser-only regression fixture. Never used by the product build.
fn main() {}

#[cfg(target_arch = "wasm32")]
mod browser {
    use futures_channel::oneshot;
    use js_sys::Function;
    use std::task::{Context, Waker};
    use vhalla_browser_storage::{
        browser::IndexedStorage, Error, Image, Namespace, Slot, MAX_PENDING_OPENS,
    };
    use wasm_bindgen::prelude::*;
    use wasm_bindgen_futures::{spawn_local, JsFuture};

    fn fail(error: impl std::fmt::Debug) -> JsValue {
        JsValue::from_str(&format!("qualification: {error:?}"))
    }
    fn ensure(value: bool, message: &str) -> Result<(), JsValue> {
        if value {
            Ok(())
        } else {
            Err(fail(message))
        }
    }
    /// Drive a harness mode; modes may return a promise that must settle before
    /// the next assertion. Plain values resolve immediately.
    async fn control(hook: &Function, mode: &str, arg: &JsValue) -> Result<JsValue, JsValue> {
        let value = hook.call2(&JsValue::NULL, &mode.into(), arg)?;
        JsFuture::from(js_sys::Promise::resolve(&value)).await
    }
    /// Replicates the adapter's `vhalla-browser-storage-v1-<hex>` naming so the
    /// harness can hold foreign connections against the exact database.
    fn database_name(raw: &[u8]) -> String {
        use std::fmt::Write;
        let mut name = String::from("vhalla-browser-storage-v1-");
        for byte in raw {
            write!(&mut name, "{byte:02x}").expect("writing a bounded String");
        }
        name
    }
    /// Poll an open future once so it posts its request and owns a pending slot,
    /// then report it still pending so the caller can cancel by dropping it.
    fn park(
        future: std::pin::Pin<
            &mut impl std::future::Future<Output = Result<IndexedStorage, Error>>,
        >,
    ) -> Result<(), JsValue> {
        let mut context = Context::from_waker(Waker::noop());
        ensure(
            future.poll(&mut context).is_pending(),
            "open resolved before a terminal event",
        )
    }
    fn vault(variant: u8) -> Result<Image, JsValue> {
        // Existing public interoperability vector; no personal key/import.
        // Storage tests framing and equality, not password authentication.
        let hex = include_str!("../../vhalla-browser-vault/vectors/v1-envelope.hex").trim();
        let mut raw: Vec<u8> = hex
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect();
        raw[30] ^= variant;
        Image::new(Slot::Vault, &[&raw]).map_err(fail)
    }

    /// Exercise the production IndexedDB adapter in a new test-owned namespace.
    /// `hook` injects browser transaction faults; it is test harness code only.
    #[wasm_bindgen]
    pub async fn qualify(raw_namespace: Vec<u8>, hook: Function) -> Result<String, JsValue> {
        let namespace = Namespace::new(raw_namespace.clone().try_into().map_err(fail)?);
        let mut storage = IndexedStorage::open(namespace).await.map_err(fail)?;
        ensure(
            storage
                .load_identity()
                .await
                .map_err(fail)?
                .vault()
                .is_none(),
            "namespace must be empty",
        )?;
        control(&hook, "require-strict", &JsValue::UNDEFINED).await?;
        let original = vault(0)?;
        let saved = storage
            .create_local_identity(&original)
            .await
            .map_err(fail)?;
        let checkpoint = Image::new(Slot::Checkpoint, &[b"retained checkpoint"]).map_err(fail)?;
        storage
            .compare_exchange(None, &checkpoint)
            .await
            .map_err(fail)?;
        ensure(!storage.needs_reopen(), "strict publication completed")?;

        control(&hook, "deny-writes", &JsValue::UNDEFINED).await?;
        let unchanged = storage.revalidate_identity(&saved).await.map_err(fail)?;
        ensure(unchanged == saved, "read-only exact pair changed")?;
        ensure(
            !storage.needs_reopen(),
            "read-only unlock invalidated handle",
        )?;
        control(&hook, "assert-no-write", &JsValue::UNDEFINED).await?;
        let changed = vault(1)?;
        ensure(
            storage.replace_identity(&saved, &changed).await.is_err(),
            "quota refused write reported success",
        )?;
        ensure(
            storage.needs_reopen(),
            "failed write did not require reopen",
        )?;
        drop(storage);
        let mut storage = IndexedStorage::open(namespace).await.map_err(fail)?;
        ensure(
            storage.revalidate_identity(&saved).await.map_err(fail)? == saved,
            "quota changed saved identity",
        )?;

        for mode in ["ignored-options", "throw-durability"] {
            control(&hook, mode, &JsValue::UNDEFINED).await?;
            ensure(
                storage.replace_identity(&saved, &changed).await.is_err(),
                "unsupported durability accepted identity write",
            )?;
            ensure(
                storage.needs_reopen(),
                "unsupported durability kept write handle ready",
            )?;
            control(&hook, "assert-no-mutation", &JsValue::UNDEFINED).await?;
            drop(storage);
            storage = IndexedStorage::open(namespace).await.map_err(fail)?;
            ensure(
                storage.revalidate_identity(&saved).await.map_err(fail)? == saved,
                "durability failure changed identity",
            )?;
            let next = Image::new(Slot::Checkpoint, &[b"must not be published"]).map_err(fail)?;
            ensure(
                storage
                    .compare_exchange(Some(&checkpoint), &next)
                    .await
                    .is_err(),
                "unsupported durability accepted generic write",
            )?;
            control(&hook, "assert-no-mutation", &JsValue::UNDEFINED).await?;
            drop(storage);
            storage = IndexedStorage::open(namespace).await.map_err(fail)?;
            ensure(
                storage.load(Slot::Checkpoint).await.map_err(fail)? == Some(checkpoint.clone()),
                "durability failure changed checkpoint",
            )?;
        }

        control(&hook, "abort-write", &JsValue::UNDEFINED).await?;
        ensure(
            storage.replace_identity(&saved, &changed).await.is_err(),
            "aborted identity write acknowledged",
        )?;
        ensure(storage.needs_reopen(), "abort kept handle ready")?;
        drop(storage);
        storage = IndexedStorage::open(namespace).await.map_err(fail)?;
        ensure(
            storage.revalidate_identity(&saved).await.map_err(fail)? == saved,
            "abort changed retained pair",
        )?;

        control(&hook, "require-strict", &JsValue::UNDEFINED).await?;
        let mut stale_peer = IndexedStorage::open(namespace).await.map_err(fail)?;
        let replaced = stale_peer
            .replace_identity(&saved, &changed)
            .await
            .map_err(fail)?;
        ensure(
            storage.revalidate_identity(&saved).await == Err(Error::Stale),
            "stale tab unlocked old encrypted vault",
        )?;
        ensure(storage.needs_reopen(), "stale tab stayed ready")?;
        drop(storage);
        let mut storage = IndexedStorage::open(namespace).await.map_err(fail)?;
        ensure(
            storage.revalidate_identity(&replaced).await.map_err(fail)? == replaced,
            "new exact identity cannot unlock",
        )?;

        // Queued pending opens still occupy bounded slots; dropping a pending
        // open must close its late connection and release the slot.
        let mut alt_raw = raw_namespace.clone();
        alt_raw[0] ^= 0x5a;
        let alt = Namespace::new(alt_raw.as_slice().try_into().map_err(fail)?);
        control(&hook, "hold-create", &database_name(&alt_raw).into()).await?;
        let mut pending = Vec::new();
        for _ in 0..MAX_PENDING_OPENS - 1 {
            let (sender, receiver) = oneshot::channel();
            spawn_local(async move {
                let _ = sender.send(IndexedStorage::open(alt).await);
            });
            pending.push(receiver);
        }
        // Let the spawned opens acquire their slots behind the held upgrade.
        control(&hook, "tick", &JsValue::UNDEFINED).await?;
        {
            let mut canceled = std::pin::pin!(IndexedStorage::open(alt));
            park(canceled.as_mut())?;
            // The future drops here mid-await: the pending request keeps its
            // slot until its late terminal event.
        }
        ensure(
            matches!(IndexedStorage::open(alt).await, Err(Error::Bounds)),
            "pending opens exceeded the bounded slot count",
        )?;
        control(&hook, "release-create", &JsValue::UNDEFINED).await?;
        let mut held = Vec::new();
        for receiver in pending {
            held.push(receiver.await.map_err(fail)?.map_err(fail)?);
        }
        // The canceled request's late success must have closed its connection:
        // otherwise this foreign upgrade would stay blocked forever. Chromium
        // reports `blocked` only when connections linger, so a prompt close is
        // the passing verdict.
        let verdict = control(&hook, "bump-version", &database_name(&alt_raw).into()).await?;
        if verdict.as_string().as_deref() == Some("stuck") {
            return Err(fail("canceled open leaked its connection"));
        }
        for handle in &mut held {
            ensure(handle.needs_reopen(), "version change left a handle ready")?;
        }
        drop(held);
        ensure(
            IndexedStorage::open(alt).await.is_err(),
            "newer database version reopened as v1",
        )?;

        // An open queued behind a pending delete must abort its own upgrade
        // when the awaiting future was canceled mid-queue.
        let mut third_raw = raw_namespace.clone();
        third_raw[0] ^= 0xa5;
        let third = Namespace::new(third_raw.as_slice().try_into().map_err(fail)?);
        control(&hook, "hold-and-delete", &database_name(&third_raw).into()).await?;
        {
            let mut queued = std::pin::pin!(IndexedStorage::open(third));
            park(queued.as_mut())?;
            // Dropping mid-queue cancels the open; the late upgrade aborts.
        }
        control(&hook, "release-blocker", &JsValue::UNDEFINED).await?;
        let reopened = IndexedStorage::open(third).await.map_err(fail)?;
        ensure(
            !reopened.needs_reopen(),
            "canceled queued open wedged the namespace",
        )?;

        // A foreign version bump on the live connection must close it and
        // latch NeedsReopen; the same namespace then refuses v1 opens.
        let verdict = control(&hook, "bump-version", &database_name(&raw_namespace).into()).await?;
        if verdict.as_string().as_deref() == Some("stuck") {
            return Err(fail("a live connection refused the foreign upgrade"));
        }
        ensure(
            storage.needs_reopen(),
            "foreign version change kept the handle ready",
        )?;
        ensure(
            storage.load(Slot::Checkpoint).await.is_err(),
            "closed connection still served reads",
        )?;
        ensure(
            IndexedStorage::open(namespace).await.is_err(),
            "v2 database accepted a v1 open",
        )?;
        control(&hook, "finish", &JsValue::UNDEFINED).await?;
        Ok("strict identity and generic writes; readonly unlock under denied writes; ignored/throwing durability refuses before mutations; abort retains state; stale tab refuses; queued opens bounded, canceled pending open closed, canceled queued upgrade aborted; foreign version change closes handles".into())
    }

    /// Write one committed checkpoint per step until the realm is terminated;
    /// `progress` observes each committed index. Realm teardown mid-write must
    /// leave only fully committed states.
    #[wasm_bindgen]
    pub async fn interruptible(raw_namespace: Vec<u8>, progress: Function) -> Result<(), JsValue> {
        let namespace = Namespace::new(raw_namespace.as_slice().try_into().map_err(fail)?);
        let mut storage = IndexedStorage::open(namespace).await.map_err(fail)?;
        let mut expected: Option<Image> = None;
        for index in 0u32..10_000 {
            let next = Image::new(Slot::Checkpoint, &[&index.to_be_bytes()]).map_err(fail)?;
            storage
                .compare_exchange(expected.as_ref(), &next)
                .await
                .map_err(fail)?;
            let _ = progress.call1(&JsValue::NULL, &JsValue::from(index));
            expected = Some(next);
        }
        Ok(())
    }

    /// After an interrupted writer, the retained checkpoint must be a
    /// well-formed committed image at or beyond every observed progress index.
    #[wasm_bindgen]
    pub async fn verify_interrupted(
        raw_namespace: Vec<u8>,
        minimum: u32,
    ) -> Result<String, JsValue> {
        let namespace = Namespace::new(raw_namespace.as_slice().try_into().map_err(fail)?);
        let mut storage = IndexedStorage::open(namespace).await.map_err(fail)?;
        let image = storage
            .load(Slot::Checkpoint)
            .await
            .map_err(fail)?
            .ok_or_else(|| fail("interrupted namespace lost its committed checkpoint"))?;
        let mut records = image.records();
        let index = records
            .next()
            .and_then(|record| <[u8; 4]>::try_from(record).ok())
            .map(u32::from_be_bytes)
            .ok_or_else(|| fail("committed checkpoint lost its framing"))?;
        ensure(records.next().is_none(), "checkpoint gained extra records")?;
        ensure(
            index >= minimum,
            "retained state regressed below an observed commit",
        )?;
        Ok(format!(
            "interrupted writer retained committed checkpoint {index}"
        ))
    }
}
