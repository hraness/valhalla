# Bounded artifact sizes (spike 2)

Disposable reference for vhalla (valhalla), excluded from the maintained
workspace. Spike 2 of
[the Platonik session adapter plan](../../kb/plans/valhalla-platonik-session-adapter.md):
do 64 KiB blocks, 128 blocks, and per-`(segment, case)` granularity fit real
sizes, and do the widest `GameManifest` and `SessionOpen` fit one signed frame?

Every number comes from the real types at the pinned Platonik commit
`5eedec07`, never from an estimate.

## What it measures

- **(a) Platonik artifacts.** For the six fixtures and the 21 `bridge-v1`
  suite cases, the compact `serde_json::to_vec` size of the `Experiment`, the
  `RunResult` (`platonik_core::run`), and the whole `Receipt`
  (`platonik_core::check::make_receipt`). Those are the bytes an
  `InnerArtifactId` of kind 1, 2, and 3 hashes.
- **(b) One adapter frame trace.** The witness corpus worst case
  (`crates/vhalla-witness/tests/vectors/worst-case.txt`) through
  `platform::run_observed` with an observer that appends
  `codec::encode_state` of every frame, framed as
  `tick:u32be | complete:u8 | len:u32be | encode_state`. That is one
  `(segment, case)` artifact.
- **(c) Assembly.** The largest measured artifact, a 1.25 MB trace, and the
  8 MiB, 128-block ceiling driven through `ArtifactAssembly` natively and
  through the browser record mapping, with peak retained bytes reported
  against the plan's 1.25 x ceiling. Then 64 sequential trace fetches, which
  is what a full eight-segment, eight-case session costs under the plan's
  peak-retention accounting.
- **(d) One signed frame.** The widest `GameManifest` and `SessionOpen`
  against `vhalla_crypto::MAX_SIGNED_BODY_BYTES`, with the margins printed.

## Measured

| Measurement | Result |
| --- | --- |
| Largest corpus `Experiment` | 3,292 bytes, 1 block (`bridge-v1-ark-plan-a-memory-cleared`) |
| Largest corpus `RunResult` | 123,351 bytes, 2 blocks (`bridge-v1-ark-plan-a-constant-a`) |
| Largest corpus `Receipt` | 126,655 bytes, 2 blocks (`bridge-v1-ark-plan-a-alternating`) |
| Largest known Platonik receipt (outside this corpus) | 7,141,362 bytes, 109 of 128 blocks |
| Worst-case frame trace, one `(segment, case)` | 302,508 bytes over 129 frames, 5 blocks |
| Assembly peak, every size and both paths | exactly 1.0000 x the artifact |
| Transport buffers beside it | 65,536 bytes native, 135,872 bytes browser, both constants |
| 8 MiB ceiling, 128 blocks | 1.0078 x native, 1.0162 x browser, 129 SHA-256 invocations |
| 64 sequential trace fetches | peak 368,044 bytes, 4.39 % of the 8 MiB session budget |
| Widest `GameManifest` | 903 bytes, 64,438 bytes of margin |
| Widest `SessionOpen` | 1,214 bytes, 64,127 bytes of margin |

The 1.25 x ceiling is charged against the assembly, which is what
`SessionLimits.max_artifact_bytes` bounds. The transport's in-flight buffers
are a constant of one block and its records, so they are bounded separately
rather than folded into a ratio that a two-block artifact could never meet.

## Boundary

Sizes are evidence about this corpus at this pin. They are not a storage
assumption, not a compression claim (v1 carries none), and not a security
result. A measured receipt fits one artifact; that says nothing about whether
its contents are true.

## Verify

```sh
cargo fmt --manifest-path prototypes/game-artifact-sizes/Cargo.toml -- --check
cargo test --manifest-path prototypes/game-artifact-sizes/Cargo.toml --locked -- --nocapture
cargo clippy --manifest-path prototypes/game-artifact-sizes/Cargo.toml --all-targets --locked -- -D warnings
```

The first run fetches the pinned `platonik-core` commit. The suite runs in
about ten seconds.
