//! Isolated archive namespace/fault spike; never linked by the browser product.
fn main() {}

#[cfg(any(target_arch = "wasm32", test))]
#[path = "../../../prototypes/browser-archive-recovery/namespace.rs"]
mod namespace;

#[cfg(target_arch = "wasm32")]
#[path = "../../../prototypes/browser-archive-recovery/journey.rs"]
mod journey;
