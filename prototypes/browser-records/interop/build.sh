#!/bin/bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
bindgen_command="${VHALLA_WASM_BINDGEN:-wasm-bindgen}"
if [[ "$("$bindgen_command" --version)" != "wasm-bindgen 0.2.108" ]]; then
  printf '%s\n' 'This locked experiment requires wasm-bindgen CLI 0.2.108.' >&2
  exit 1
fi
cargo build --bin vhalla-webrtc-listener --locked --offline
if [[ -n "${VHALLA_WASM_RUSTC:-}" ]]; then
  RUSTC="$VHALLA_WASM_RUSTC" cargo build --lib --target wasm32-unknown-unknown --locked --offline
else
  cargo build --lib --target wasm32-unknown-unknown --locked --offline
fi
"$bindgen_command" --target web --out-dir site/pkg target/wasm32-unknown-unknown/debug/vhalla_browser_webrtc_spike.wasm
