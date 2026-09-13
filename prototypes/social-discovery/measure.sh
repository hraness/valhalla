#!/bin/sh
set -eu
root=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
if [ "$#" -gt 0 ]; then
  # Optional receipt path is explicit and must not replace existing evidence.
  set -C
  exec > "$1" 2>&1
fi
date -u '+measured_at=%Y-%m-%dT%H:%M:%SZ'
uname -sm
rustc -V
cargo build --manifest-path "$root/Cargo.toml" --example measure --release --locked --offline
for bytes in 256 4096; do
  for count in 64 256 1024 4096; do
    /usr/bin/time -l "$root/target/release/examples/measure" "$count" "$bytes"
  done
done
