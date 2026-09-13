# Dioxus preview assembler

This standalone Rust utility creates a fresh, deterministic web preview
directory from one exact `wasm-bindgen` output directory and one checked CSS
file. It copies generated JavaScript, WASM, declarations and snippets, emits
the minimal `#main` shell required by Dioxus, and records SHA-256/size rows in
`SHA256SUMS`. Existing output is rejected, symlinks and oversized files are
rejected, and only one root binding JS and one `_bg.wasm` are admitted.

The utility does not author application JavaScript or provide a protocol
runtime. The generated binding closure remains a toolchain artifact; callers
must pin and record the Dioxus and wasm-bindgen versions before invoking it.

```sh
cargo run --manifest-path prototypes/dioxus-preview-assembler/Cargo.toml -- \
  /tmp/vhalla-preview /tmp/wasm-bindgen-output prototypes/dioxus-ui/assets/screen.css
```
