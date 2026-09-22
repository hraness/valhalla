//! Synthetic account-derived private custody over actual IndexedDB and MLS.
//! Separate from the group fixture so its existing runtime budget is unchanged.
//! No user import, product session, network, secret getter or generic signer.
fn main() {}

#[cfg(target_arch = "wasm32")]
#[path = "private_custody_indexeddb/journey.rs"]
mod journey;

#[cfg(target_arch = "wasm32")]
mod browser {
    use vhalla_browser_storage::Namespace;
    use wasm_bindgen::prelude::*;

    /// Same bounded isolated Window/worker harness as private_mls_indexeddb.
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
