#![forbid(unsafe_code)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    vhalla_dioxus_native_closed_spike::launcher::run()
}
