//! Browser entry point; all product logic is authored in Rust.
#[cfg(all(target_arch = "wasm32", feature = "private-rooms"))]
#[path = "../private/wire.rs"]
pub mod private_wire;
#[cfg(all(target_arch = "wasm32", feature = "private-rooms"))]
pub use ui::private as private_rooms;
#[cfg(all(target_arch = "wasm32", feature = "private-rooms"))]
#[path = "../private/panel.rs"]
mod private_panel;
#[cfg(all(
    target_arch = "wasm32",
    feature = "private-rooms",
    feature = "local-qualification"
))]
pub use ui::private_qualification::{qualify_private_cancel, qualify_private_session};
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
        #[cfg(feature = "private-rooms")]
        private_panel::start();
    }
}
