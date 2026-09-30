//! Capture immutable native release identity only in the official build.
fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=VHALLA_BUILD_RELEASE_TAG");
    println!(
        "cargo:rustc-env=VHALLA_COMPILED_TARGET={}",
        std::env::var("TARGET").expect("Cargo target")
    );
    if let Ok(tag) = std::env::var("VHALLA_BUILD_RELEASE_TAG") {
        let version = std::env::var("CARGO_PKG_VERSION").expect("Cargo package version");
        assert_eq!(
            tag,
            format!("v{version}"),
            "release build tag must match the package version"
        );
        println!("cargo:rustc-env=VHALLA_COMPILED_RELEASE_TAG={tag}");
    } else {
        println!("cargo:rustc-env=VHALLA_COMPILED_RELEASE_TAG=");
    }
}
