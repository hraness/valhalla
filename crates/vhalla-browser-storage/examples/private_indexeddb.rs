//! Synthetic private IndexedDB fixture. Not a shipping or network artifact.
fn main() {}

#[cfg(target_arch = "wasm32")]
mod browser {
    use ed25519_dalek::SigningKey;
    use vhalla_browser_storage::{browser::private_rooms::qualification, Namespace};
    use vhalla_private_kernel::Context;
    use vhalla_private_protocol::{AnchorId, Key, PrivateRoomScope, RoomId};
    use wasm_bindgen::prelude::*;
    /// Execute only a new random namespace provided by the isolated runner.
    #[wasm_bindgen]
    pub async fn qualify(
        raw_namespace: Vec<u8>,
        hook: js_sys::Function,
    ) -> Result<String, JsValue> {
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
        qualification::run(namespace, contexts, hook).await
    }
}
