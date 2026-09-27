# Reachable addresses for peer discovery

These local Malachite packages let a node behind a TCP proxy advertise the
proxy endpoint in its signed peer record. A joining node can then discover
and dial other seeds through one bootstrap peer.

## Source and licence

`malachite-config`, `malachite-app` and `malachite-network` contain the
corresponding `code/crates/` sources from
[`circlefin/malachite` at `72143f6c99a98452b587e1c392bdb80944eb2232`](https://github.com/circlefin/malachite/tree/72143f6c99a98452b587e1c392bdb80944eb2232/code/crates).
Each directory retains the upstream Apache-2.0 `LICENSE` and original crate
manifest as `Cargo.toml.orig`. `upstream-files.sha256` records the copied
Rust sources, manifests and licences before the local changes.
`discovery.patch` records the Rust changes against that revision, including
the local tests.

The root manifest selects these three unpublished packages with
`[patch."https://github.com/circlefin/malachite"]`. The remaining Malachite
packages use the same original Git revision. The patch does not change the
engine, discovery wire format, signature checks or validator authentication.

The local manifests expand upstream workspace inheritance into explicit
package metadata, dependencies and lints. Dependency features are the union
of workspace and crate features. Internal path dependencies become Git
dependencies pinned to the original revision; the root patch selects the
three local replacements. All dependency versions and defaults match the
upstream declared requirements. The unused `libp2p-stream` development
dependency is omitted; none of the copied source or tests imports it.
`publish` is false and `readme` points to this file.

The three packages are explicit workspace members so their tests run against
the repository lockfile. Workspace-wide tests also include their retained
upstream unit tests. The lockfile resolves upstream's optional Borsh feature
and TOML test dependencies, which were absent when these packages were only
dependencies of Valhalla. The manifests retain the upstream lints.

## Behaviour

`P2pConfig.external_addrs` defaults to an empty list, including when an older
configuration omits the field. The app maps it into the network configuration.
Before the network starts, each configured address is registered through
libp2p's `Swarm::add_external_address`.

With explicit addresses, Identify uses `with_hide_listen_addrs(true)`. Its
address list and signed peer record contain those endpoints, excluding
container and loopback listeners. With an empty list, Identify advertises
listeners as it does upstream. The socket bind address is independent of the
advertised addresses.

Malachite's full peer exchange relays the signed records it receives. Merely
adding provider endpoints to a seed's bootstrap list cannot repair a record
that advertises loopback addresses: another peer cannot rewrite that signed
record. Operators must configure endpoints that route back to this node and
keep the node's identity stable.

## Tests and maintenance

Run from the repository root so the tests use its patch table and lockfile:

```console
cargo test --locked -p arc-malachitebft-config -p arc-malachitebft-app -p arc-malachitebft-network --all-targets --all-features
```

The network tests start the production network service and receive its
Identify message over a local TCP connection. They verify the peer-record
signature and check explicit DNS and IPv6 advertisements, exclusion of the
private listener and compatibility when no override is configured. The
configuration tests cover deserialisation and forwarding into the network.
They do not establish reachability of a provider endpoint; live discovery
tests supply that evidence.

When updating Malachite, compare these changes with upstream, run the tests
and the repository checks, then remove the three local packages and patch
entries together once upstream offers equivalent address configuration.
