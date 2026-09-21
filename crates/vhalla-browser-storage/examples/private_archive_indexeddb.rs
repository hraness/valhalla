//! Closed synthetic archive qualification over actual MLS and strict IndexedDB.
//! This separate example is never imported by the production browser app.
fn main() {}

#[cfg(target_arch = "wasm32")]
#[path = "private_archive_indexeddb/journey.rs"]
mod journey;

#[cfg(target_arch = "wasm32")]
mod browser {
    use vhalla_browser_storage::Namespace;
    use wasm_bindgen::prelude::*;

    /// Same bounded isolated Window/worker harness as the maintained MLS fixture.
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
