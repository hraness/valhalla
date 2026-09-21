//! Synthetic continuity-receipt IndexedDB fixture. No listener or product route.
fn main() {}

#[cfg(target_arch = "wasm32")]
#[path = "continuity_indexeddb/fixture.rs"]
mod fixture;
#[cfg(target_arch = "wasm32")]
#[path = "continuity_indexeddb/journey.rs"]
mod journey;

#[cfg(target_arch = "wasm32")]
/// Exercise bounded receipt recovery in the maintained synthetic Window/worker runner.
#[wasm_bindgen::prelude::wasm_bindgen]
pub async fn qualify(
    raw_namespace: Vec<u8>,
    hook: js_sys::Function,
) -> Result<String, wasm_bindgen::JsValue> {
    let namespace = vhalla_browser_storage::Namespace::new(
        raw_namespace
            .try_into()
            .map_err(|_| wasm_bindgen::JsValue::from_str("namespace length"))?,
    );
    journey::run(namespace, hook).await
}
