#!/bin/sh
# Native and wasm32 trace-head parity and timing over the committed vectors.
set -eu
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
manifest="$script_dir/Cargo.toml"
output=${PARITY_OUTPUT_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/vhalla-game-trace.XXXXXX")}
mkdir -p "$output"
bindgen=${BINDGEN:-wasm-bindgen}
node=${NODE:-node}
cargo_native=${CARGO:-cargo}
cargo_wasm=${WASM_CARGO:-$cargo_native}
target=${CARGO_TARGET_DIR:-$script_dir/target}
CARGO_TARGET_DIR="$target" "$cargo_native" build --manifest-path "$manifest" --release --example native --locked
"$target/release/examples/native" > "$output/native.txt"
CARGO_TARGET_DIR="$target" "$cargo_wasm" build --manifest-path "$manifest" --release --lib --target wasm32-unknown-unknown --locked
"$bindgen" --target nodejs --out-dir "$output/glue" "$target/wasm32-unknown-unknown/release/game_trace_cost.wasm"
"$node" "$script_dir/verify.cjs" "$output/glue/game_trace_cost.js" "$output/native.txt" "$output/wasm.txt"
printf 'Artifacts: %s\n' "$output"
