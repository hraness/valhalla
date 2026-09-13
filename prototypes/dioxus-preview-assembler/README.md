# Dioxus preview assembler

This standalone Rust utility creates a fresh, deterministic web preview
directory from one exact `wasm-bindgen` output directory and one checked CSS
file. It copies generated JavaScript, WASM, declarations and snippets, emits
the minimal `#main` shell required by Dioxus, and records SHA-256/size rows in
`SHA256SUMS`. Existing output is rejected, symlinks and oversized files are
rejected, and only one root binding JS and one `_bg.wasm` are admitted.

The generated shell carries a restrictive same-origin Content-Security-Policy:
the one module bootstrap is admitted by its exact SHA-256 hash, WebAssembly is
enabled through `wasm-unsafe-eval`, and objects, forms, framing and remote
connections are denied. Asset names reject control characters and markup
delimiters before they can enter the shell or manifest. This is a packaging
boundary and does not replace response headers, origin pairing, or a live
browser security review.

The utility does not author application JavaScript or provide a protocol
runtime. The generated binding closure remains a toolchain artifact; callers
must pin and record the Dioxus and wasm-bindgen versions before invoking it.

```sh
cargo run --manifest-path prototypes/dioxus-preview-assembler/Cargo.toml -- \
  /tmp/vhalla-preview /tmp/wasm-bindgen-output prototypes/dioxus-ui/assets/screen.css
```
