//! Synthetic private IndexedDB fixture. Not a shipping or network artifact.
fn main() {}

#[cfg(target_arch = "wasm32")]
mod browser {
    use ed25519_dalek::SigningKey;
    use vhalla_browser_storage::{
        browser::private_rooms::{qualification, IndexedPrivateStore},
        Namespace,
    };
    use vhalla_private_kernel::{storage::StoreError, Context};
    use vhalla_private_protocol::{AnchorId, Key, PrivateRoomScope, RoomId};
    use wasm_bindgen::prelude::*;
    use wasm_bindgen_futures::JsFuture;

    async fn absent_database(hook: &js_sys::Function, name: &str) -> Result<(), JsValue> {
        let result = hook.call2(
            &JsValue::NULL,
            &"assert-database-absent".into(),
            &name.into(),
        )?;
        JsFuture::from(js_sys::Promise::resolve(&result)).await?;
        Ok(())
    }
    /// Execute only a new random namespace provided by the isolated runner.
    #[wasm_bindgen]
    pub async fn qualify(
        raw_namespace: Vec<u8>,
        hook: js_sys::Function,
    ) -> Result<String, JsValue> {
        let mut name = String::from("vhalla-browser-storage-v1-");
        for byte in &raw_namespace {
            use std::fmt::Write;
            write!(&mut name, "{byte:02x}").expect("synthetic database name");
        }
        let namespace = Namespace::new(
            raw_namespace
                .try_into()
                .map_err(|_| JsValue::from_str("namespace length"))?,
        );
        let contexts = std::array::from_fn(|i| Context {
            scope: PrivateRoomScope {
                room: RoomId::from_bytes([i as u8 + 1; 32]).unwrap(),
                anchor: AnchorId::from_bytes([17; 32]).unwrap(),
            },
            account: Key::from_bytes(SigningKey::from_bytes(&[3; 32]).verifying_key().to_bytes())
                .unwrap(),
            device: Key::from_bytes(SigningKey::from_bytes(&[4; 32]).verifying_key().to_bytes())
                .unwrap(),
        });
        absent_database(&hook, &name).await?;
        if !matches!(
            IndexedPrivateStore::open(namespace, contexts[0]).await,
            Err(StoreError::Uncertain)
        ) {
            return Err(JsValue::from_str(
                "absent database did not refuse existing-only open",
            ));
        }
        absent_database(&hook, &name).await?;
        qualification::run(namespace, contexts, hook).await
    }
}
