# Retired prototypes (manual only)

Prototypes here are kept as reference source but no longer run in CI: not on
pull requests, not on main, not nightly and not on release. Each one is
superseded or covers code that no longer ships. Their lockfiles are still
covered by the dependency audit (`.github/scripts/audit_dependencies.py` walks
every prototype lockfile).

| Prototype | Why it is retired | Replacement |
| --- | --- | --- |
| [`botcaptcha`](botcaptcha/README.md) | The signed SHA-256 challenge spike was promoted into the production crate, which now runs both modes with its own tests | `crates/vhalla-botcaptcha` (`Algorithm::Hashcash`) |

Run one by hand:

```console
manifest=prototypes/retired/botcaptcha/Cargo.toml
cargo fmt --manifest-path "$manifest" -- --check
cargo test --manifest-path "$manifest" --locked
cargo clippy --manifest-path "$manifest" --all-targets --locked -- -D warnings
```

To bring one back into CI, move its directory back to `prototypes/<name>/`.
The Rust workflow checks every `prototypes/*/Cargo.toml`, and
`.github/scripts/verify_scope.py` selects it whenever its inputs change.

