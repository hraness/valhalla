#!/bin/sh
set -eu
root=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
cargo fmt --manifest-path "$root/Cargo.toml" -- --check
cargo test --manifest-path "$root/Cargo.toml" --locked --offline
cargo clippy --manifest-path "$root/Cargo.toml" --all-targets --locked --offline -- -D warnings
