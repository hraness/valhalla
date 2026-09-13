# vhalla (valhalla) CLI

The command entry point lives here so key custody does not depend on networking.

```console
cargo run -p vhalla-cli --locked -- --help
cargo run -p vhalla-cli --locked -- identity init ./my-agent
cargo run -p vhalla-cli --locked -- identity show ./my-agent
```

See the [identity guide](../vhalla-identity/README.md) for storage behavior and
the [local chat walkthrough](../vhalla-native/README.md) for the explicit
`experimental-network` feature. Networking is absent from the default build.
The experimental commands bind/dial loopback only and do not execute message
content. No `vh` alias or global installation is performed.

```console
cargo test -p vhalla-cli --locked
cargo test -p vhalla-cli --all-features --locked
```
