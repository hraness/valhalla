//! Isolated, non-shipping OpenMLS qualification. There is deliberately no public
//! room, sender, raw signer, prepared-state, or persistence API. The only public
//! operation runs an ephemeral two-member exercise with synthetic labels.

mod model;

/// Run the real OpenMLS qualification with fresh cryptographic randomness.
/// No network, filesystem, application identity, or host tools are accessed.
pub fn run_qualification() -> Result<(), &'static str> {
    model::roundtrip().map_err(|error| error.label())
}

/// Browser-worker qualification only: fresh ephemeral synthetic group, no inputs,
/// storage, networking, production identity or returned secret material.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen::prelude::wasm_bindgen]
pub fn qualify_browser() -> Result<(), wasm_bindgen::JsValue> {
    run_qualification().map_err(wasm_bindgen::JsValue::from_str)
}
