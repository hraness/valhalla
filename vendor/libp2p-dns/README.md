# Scoped Hickory compatibility backport

This directory is the unpublished `libp2p-dns` 0.44.0 adapter used by the
pinned Malachite/libp2p 0.56 stack, with the upstream Hickory 0.26 migration
backported. It keeps `libp2p-core` 0.43 and `libp2p-identity` 0.2, avoiding a
consensus-engine or transport-stack upgrade to remove the active Hickory 0.25
resolver. The repository root selects it with `[patch.crates-io]` and excludes
it from workspace membership. It is not an upstream 0.44.1 release.

## Provenance and license

- Base: crates.io [`libp2p-dns` 0.44.0](https://crates.io/crates/libp2p-dns/0.44.0),
  upstream commit `d92dabcbb87c4796d46e3d312b7fa042af10279a`,
  `transports/dns`. Its normalized manifest supplies the old transport
  dependency versions.
- Migration: upstream [PR #6423](https://github.com/libp2p/rust-libp2p/pull/6423),
  commit `67669858e2ab5448575a2ee26797dccc7b8c2c17`; source taken from the
  published [`libp2p-dns` 0.45.0](https://crates.io/crates/libp2p-dns/0.45.0)
  snapshot, commit `7171dce2f90c05ba7892d4ba926abb1881db27c7`.
- MIT license and original Parity copyright are retained in `LICENSE` and the
  source header. `backport.patch` records the manifest/source changes against
  the published 0.44.0 files. `src/backport_tests.rs` is additional local test
  coverage and is not upstream code.

The adapter uses the actual published Hickory resolver 0.26.3 and therefore
its 0.26 protocol/network crates; no dependency version is disguised and no
security advisory is suppressed. The previous resolver depended on Hickory
protocol 0.25, affected by [RUSTSEC-2026-0118](https://rustsec.org/advisories/RUSTSEC-2026-0118.html)
and [RUSTSEC-2026-0119](https://rustsec.org/advisories/RUSTSEC-2026-0119.html).
Other inactive lockfile entries are reported separately by the repository
security review; this patch alone does not imply a clean raw lockfile audit.

The original 0.44.0 file SHA-256 values are:

```text
Cargo.toml  e8a19361a02c348ad3c48f47b2d3ceef14a473193c522c0d47a6e0125525f567
src/lib.rs  015f470b99b817b8f0c8caf09ab7e29cca6d62f4005d5f30ee0b5dfb0566a1fe
```

## Compatibility boundary

The `Transport` implementation still implements the 0.43 core traits.
`tokio::Transport::{system,custom}` and the resolver config/options consumed by
libp2p 0.56 and Malachite retain their call shapes. The old async-trait convention
is retained. Rust 1.88 is now required by Hickory, matching pinned Malachite.

This is a repository-scoped compatibility patch, not complete external source
compatibility for every public Hickory type that 0.44 exposed. As in upstream
0.45, `ResolveError` aliases Hickory's `NetError`, `ResolveErrorKind` is no
longer exported, and the hidden `Resolver` trait returns the new `Lookup` for
A, AAAA, and TXT queries. No current production caller implements that trait or
uses the removed error-kind type. Do not publish this package as a general
semver-compatible replacement.

## Validation and maintenance

Run the deterministic adapter tests without contacting public DNS:

```console
cargo test --manifest-path vendor/libp2p-dns/Cargo.toml --features tokio --locked -- backport_
cargo check -p vhalla-rooms-node --all-features --locked
```

The nine local tests cover IPv4/IPv6 answer filtering, mixed IP lookup,
fallback ordering, TXT multiaddress conversion, error propagation, literal-IP
pass-through, the old core transport trait, and empty/wrong-family/additional-only
responses. Unlike the upstream adapter, a successful lookup with no matching
answer returns a resolution error instead of panicking. The two retained upstream tests
(`basic_resolve`, `aggregated_dial_errors`) use public resolvers and can be run
separately for live qualification; the deterministic command does not claim
that evidence. The standalone lockfile pins this test graph.

Valhalla owns this patch until upstream supplies a compatible fixed release or
Malachite upgrades to libp2p 0.57 or later. Recheck upstream and RustSec when
updating the lockfile, run these tests and the repository gates, and remove this
directory and root patch together when the upstream path has equivalent
coverage. Do not change Malachite's pin, networking semantics, or advisory
policy merely to make this patch disappear.
