//! Real MLS over IndexedDB in a synthetic isolated Window/worker fixture only.
//! No network, account import, production activation or raw signing API.
fn main() {}

#[cfg(target_arch = "wasm32")]
#[path = "private_mls_indexeddb/journey.rs"]
mod journey;

#[cfg(target_arch = "wasm32")]
mod browser {
    use vhalla_browser_storage::Namespace;
    use wasm_bindgen::prelude::*;

    /// Run bounded real kernel journeys in a new random fixture namespace.
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
        Box::pin(super::journey::run(namespace, hook)).await
    }
}
