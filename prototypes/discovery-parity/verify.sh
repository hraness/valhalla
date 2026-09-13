#!/bin/sh
set -eu
# Build/run inside the host scheduler on Hraness hosts; CI owns its runner.
# Optional WASM_RUSTC chooses a compiler with an installed wasm32 sysroot.
# BINDGEN and NODE override tool commands; CARGO_TARGET_DIR is honored.
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
manifest="$script_dir/Cargo.toml"
output=${PARITY_OUTPUT_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/vhalla-discovery-parity.XXXXXX")}
mkdir -p "$output"
bindgen=${BINDGEN:-wasm-bindgen}
node=${NODE:-node}
target=${CARGO_TARGET_DIR:-$script_dir/target}
CARGO_TARGET_DIR="$target" cargo build --manifest-path "$manifest" --example native --locked --offline
"$target/debug/examples/native" > "$output/native.bin"
if [ -n "${WASM_RUSTC:-}" ]; then
    CARGO_TARGET_DIR="$target" RUSTC="$WASM_RUSTC" cargo build --manifest-path "$manifest" --lib --target wasm32-unknown-unknown --locked --offline
else
    CARGO_TARGET_DIR="$target" cargo build --manifest-path "$manifest" --lib --target wasm32-unknown-unknown --locked --offline
fi
"$bindgen" --target nodejs --out-dir "$output/glue" "$target/wasm32-unknown-unknown/debug/vhalla_discovery_parity.wasm"
"$node" "$script_dir/verify.cjs" "$output/glue/vhalla_discovery_parity.js" "$output/native.bin" "$output/wasm.bin"
printf 'Artifacts: %s\n' "$output"
