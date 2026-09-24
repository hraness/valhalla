# Executed discovery parity

For vhalla (valhalla), this retained fixture compares the same maintained Rust
social, discovery and attention code on native execution and WebAssembly. It is
a standalone, unpublished qualification harness; its Node glue is test tooling,
and adds no product JavaScript or TypeScript.

The fixed signed corpus has two owners, profile and channel posts, a committed
follow, exact signed owner mentions and ASCII tags, multibyte text and an inert
bidirectional-formatting character. Assertions cover:

- verified tag/mention/literal search, ASCII-only case folding and exact revisions;
- Following and integer-ranked Discover, plus channel discovery;
- a maximum-length common-prefix no-match query exhausting its work budget;
- invalid query syntax, a facet splitting a UTF-8 scalar and malformed wire UTF-8;
- private observation, explicit feedback, seen marks and canonical state codecs;
- a mention acknowledgement followed by an edited mention: the group stays read,
  the exact new update is unread, and the new tag replaces the old tag;
- stale cursor rejection and signed revision decode/signature verification.

Both executions serialize the signed archives, query coverage, exact result IDs,
text and facets, ranking components, notification identities/read state, and
private codecs. Integers use explicit fixed-width big-endian encoding. The Node
harness calls the actual WASM export, compares every byte against native output,
and fails on any assertion, trap, or mismatch. Compile-only success is insufficient.

## Run

Install a Rust compiler with `wasm32-unknown-unknown`, `wasm-bindgen-cli` exactly
`0.2.108`, Node, and the locked Cargo dependencies. The fixture adds no dependency
version beyond versions already retained by this repository. Builds run offline;
CI should fetch this manifest's locked target dependencies before invoking it.

```sh
cargo test --manifest-path prototypes/discovery-parity/Cargo.toml --locked --offline
cargo clippy --manifest-path prototypes/discovery-parity/Cargo.toml --all-targets --locked --offline -- -D warnings
cargo fmt --manifest-path prototypes/discovery-parity/Cargo.toml -- --check
sh prototypes/discovery-parity/verify.sh
```

On managed Hraness hosts, run `verify.sh` through the installed absolute
`hra-host-run --mode=shared --lane=compute` wrapper. The root integration owner
runs the complete repository gate separately.

`RUSTC` selects the normal Cargo compiler; optional `WASM_RUSTC` overrides it for
WASM only. `CARGO_TARGET_DIR`, `BINDGEN`, `NODE` and `PARITY_OUTPUT_DIR` are honored.
Otherwise the script creates a fresh temporary output directory, whose path it
prints. It retains `native.bin`, `wasm.bin` and generated Node glue for inspection;
no remote publication or application storage is involved.

## Scope

This proves deterministic semantics and canonical byte parity for the fixed
adversarial fixture under the executed toolchains. It does not qualify browser
storage, browser transport, network discovery, device clocks, embedded peak-memory
budgets, native durable persistence or arbitrary future protocol revisions. Those
have separate integration and live-qualification gates. Fixture keys are fixed
public test seeds and must never be used for a real identity.
