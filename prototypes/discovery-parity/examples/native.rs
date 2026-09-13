//! Emit the same asserted fixture bytes that the WASM entry point returns.
use std::io::Write;
fn main() {
    std::io::stdout()
        .lock()
        .write_all(&vhalla_discovery_parity::fixture_bytes())
        .unwrap();
}
