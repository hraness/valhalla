//! Browser entry point; all product logic is authored in Rust.
#[cfg(target_arch = "wasm32")]
#[path = "../network.rs"]
mod network;
#[cfg(target_arch = "wasm32")]
#[path = "../transport.rs"]
mod transport;
#[cfg(target_arch = "wasm32")]
#[path = "../ui.rs"]
mod ui;
fn main() {
    #[cfg(target_arch = "wasm32")]
    {
        ui::start();
        network::start();
    }
}
