#!/bin/sh
# Native and wasm32 session replay parity over the two frozen game vectors.
# WASM_CARGO chooses a cargo with an installed wasm32 sysroot; BINDGEN and
# NODE override tool commands; CARGO_TARGET_DIR is honored.
set -eu
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
manifest="$script_dir/Cargo.toml"
output=${PARITY_OUTPUT_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/vhalla-game-parity.XXXXXX")}
mkdir -p "$output"
bindgen=${BINDGEN:-wasm-bindgen}
node=${NODE:-node}
cargo_native=${CARGO:-cargo}
cargo_wasm=${WASM_CARGO:-$cargo_native}
target=${CARGO_TARGET_DIR:-$script_dir/target}
CARGO_TARGET_DIR="$target" "$cargo_native" build --manifest-path "$manifest" --release --example native --locked
"$target/release/examples/native" > "$output/native.txt"
CARGO_TARGET_DIR="$target" "$cargo_wasm" build --manifest-path "$manifest" --release --lib --target wasm32-unknown-unknown --locked
"$bindgen" --target nodejs --out-dir "$output/glue" "$target/wasm32-unknown-unknown/release/game_wasm_parity.wasm"
"$node" "$script_dir/verify.cjs" "$output/glue/game_wasm_parity.js" "$output/native.txt" "$output/wasm.txt"
printf 'Artifacts: %s\n' "$output"
