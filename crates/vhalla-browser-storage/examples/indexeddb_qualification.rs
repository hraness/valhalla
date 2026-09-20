//! Synthetic browser-only regression fixture. Never used by the product build.
fn main() {}

#[cfg(target_arch = "wasm32")]
mod browser {
    use js_sys::Function;
    use vhalla_browser_storage::{browser::IndexedStorage, Error, Image, Namespace, Slot};
    use wasm_bindgen::prelude::*;

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
    fn control(hook: &Function, mode: &str) -> Result<(), JsValue> {
        hook.call1(&JsValue::NULL, &mode.into()).map(|_| ())
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
        let namespace = Namespace::new(raw_namespace.try_into().map_err(fail)?);
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
        control(&hook, "require-strict")?;
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

        control(&hook, "deny-writes")?;
        let unchanged = storage.revalidate_identity(&saved).await.map_err(fail)?;
        ensure(unchanged == saved, "read-only exact pair changed")?;
        ensure(
            !storage.needs_reopen(),
            "read-only unlock invalidated handle",
        )?;
        control(&hook, "assert-no-write")?;
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
            control(&hook, mode)?;
            ensure(
                storage.replace_identity(&saved, &changed).await.is_err(),
                "unsupported durability accepted identity write",
            )?;
            ensure(
                storage.needs_reopen(),
                "unsupported durability kept write handle ready",
            )?;
            control(&hook, "assert-no-mutation")?;
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
            control(&hook, "assert-no-mutation")?;
            drop(storage);
            storage = IndexedStorage::open(namespace).await.map_err(fail)?;
            ensure(
                storage.load(Slot::Checkpoint).await.map_err(fail)? == Some(checkpoint.clone()),
                "durability failure changed checkpoint",
            )?;
        }

        control(&hook, "abort-write")?;
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

        control(&hook, "require-strict")?;
        let mut other = IndexedStorage::open(namespace).await.map_err(fail)?;
        let replaced = other
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
        control(&hook, "finish")?;
        Ok("strict identity and generic writes; readonly unlock under denied writes; ignored/throwing durability refuses before mutations; abort retains state; stale tab refuses".into())
    }
}
