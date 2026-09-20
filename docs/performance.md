# Public activity and replay performance

These are reproducible synthetic local measurements, not a production capacity recommendation. They measure real signatures, certificate checks and file/directory syncs. The examples add no production behavior.

## Environment and reproduction

Measured on Apple M4 Max, 16 physical/logical cores, 128 GiB RAM, macOS 26.5.2 (25F84), Rust/Cargo 1.98.1, optimized release binaries. Work ran in shared HRA heavy compute slots with warm filesystem caches; it was not CPU or disk isolated. Compiler time is excluded from the runtime measurements.

From the repository root, build the two examples once with the same toolchain:

```sh
CARGO_BIN="$HOME/.rustup/toolchains/1.98.1-aarch64-apple-darwin/bin/cargo"
RUSTC_BIN="$HOME/.rustup/toolchains/1.98.1-aarch64-apple-darwin/bin/rustc"
"$HOME/.bun/bin/hra-host-run" --mode=heavy --lane=compute --label=valhalla-performance-build -- \
  "$CARGO_BIN" --config "build.rustc=\"$RUSTC_BIN\"" build --release --locked \
  -p vhalla-room-activity-store -p vhalla-public-client \
  --example performance --example replay_performance
```

The timed executable commands were:

```text
/usr/bin/time -lp target/release/examples/performance ABSOLUTE_NEW_ACTIVITY_HOME 1000
/usr/bin/time -lp target/release/examples/replay_performance ABSOLUTE_NEW_REPLAY_HOME 1000
/usr/bin/time -lp target/release/examples/performance ANOTHER_NEW_ACTIVITY_HOME 10000
/usr/bin/time -lp target/release/examples/replay_performance ANOTHER_NEW_REPLAY_HOME 10000
```

Schedule each timed command through the installed heavy compute wrapper too. Each home must be new and absolute. The examples retain all generated data and write `metrics.tsv` only after completion. They refuse other counts except the explicitly supported 100,000 and check a 1,200-second cooperative deadline between operations. The qualification also supervised the two 1,000 runs with a shared 540-second deadline, and each 10,000 run separately with an 840-second process-group deadline and kill/reap on timeout. A filesystem call can exceed a cooperative deadline: use a supervised outer timeout and preserve partial evidence. No 100,000 run was attempted after the observed 10,000 timeout.

The release build succeeded with a local, nonfatal `rust-objcopy`/`libLLVM.dylib` debug-stripping warning for each executable. The optimized executables ran. This does not qualify a different compiler configuration or rebuilt binary automatically.

## Measured results

| Measurement | 1,000 operations | 10,000 operations |
|---|---:|---:|
| Activity sign + verify + durable append |64.671s (15.46 events/s)|incomplete at840s; retained HEAD9,879|
| Activity canonical signing/decoding/strict verification only |0.155s total|not available for interrupted activity run|
| Author lookup, context and append publication |64.513s total|not available for interrupted activity run|
| Append p50 / p95 / p99 |64.885 /78.905 /93.976ms|not available for interrupted activity run|
|20 reopen + verified author-head reads |18.828ms total|not available for interrupted activity run|
| Full verified activity pagination |249.628ms,16 pages|not available for interrupted activity run|
|100 exact retained retries |64.430ms total|not available for interrupted activity run|
|1,000 empty activity-page polls |102.332ms total|not available for interrupted activity run|
| Signed/certified journal creation + sync |52.806s|480.551s|
| Full certified disk replay from genesis |183.103ms|1.758s|
| Simulated native4096/30s replay budget |complete,173.707ms|refused at4096,688.543ms|
|1,000 idle published-tip reads |54.718ms|51.038ms|
| Activity / journal allocated regular-file bytes |8,204,288 /8,196,096|activity unavailable /81,924,096|

Whole-process `time -lp`: the 1,000-event activity run took 65.76s real, 1.14s user, 4.65s system, with 3,112,960-byte maximum RSS. The 1,000-bundle replay run took 53.79s real, 0.63s user, 2.59s system, with 7,847,936-byte maximum RSS. At 10,000 bundles it took 483.19s real, 6.57s user, 30.25s system, with 7,979,008-byte maximum RSS. All complete phases passed their exact final-state checks.

The incomplete activity run was stopped at 840 seconds. Read-only inspection found a checksum-valid local HEAD at 9,879 records, 5,996,553 accounted immutable bytes, and a retained 828-byte intent. The interrupted operation was not recovered or discarded. That HEAD observation is not an acknowledgement count or a successful 10,000-operation measurement; final latency percentiles, paging time and process RSS are unavailable for that run.

At 1,000 events, signing/decoding/strict verification took 0.155 seconds, while author lookup, registry context and durable append took 64.513 seconds, over 99.7% of append wall time. This identifies the publication path as the useful first optimization target in this fixture. It does not isolate individual kernel/fsync latency or establish a public request rate.

## What the examples include

[Activity storage example](../crates/vhalla-room-activity-store/examples/performance.rs) uses a real owner-created room and signed public policy, one full-key author and fixed small text. Every event is canonically signed, decoded and strictly verified before ordinary admission. Append includes current-author lookup, current registry context, intent publication, immutable record/sequence-index writes, author/global head publication and cleanup with actual syncs. Further phases measure exact retries, reopen plus verified author-head reads, full 64-record pagination with chain verification, empty-page polling and 100 ms passive idle. Memory holds one last event and bounded latency samples, not all history.

[Certified replay example](../crates/vhalla-public-client/examples/replay_performance.rs) begins with real room creation and an owner-signed public policy, then generates empty batches with 3-of-4 Ed25519 certificates and publishes them through the journal. A freshly decoded genesis client replays exact disk bytes in 32-bundle pages, checks a retained midpoint and the exact final published frontier/bundle. Replay includes certificate/application verification and no new durable writes. This fixed small application state makes it a best-case history-length baseline, not a busy registry or maximal social archive. A separate pass simulates the native no-profile 4,096-bundle/30-second budget; it does not call the private CLI function.

Reported allocated bytes sum regular-file `st_blocks * 512`; they exclude directories and filesystem overhead. Logical file bytes, accounted immutable history bytes and actual allocated disk bytes differ. Whole-process maximum RSS comes from macOS `time -lp`; the filesystem footprint walk and fixed passive idle are in whole-process time, outside the core operation timers. Passive idle is elapsed wall time, not energy measurement. Filesystem counters reported zero and were not interpreted as absence of I/O.

Generation warmed the filesystem cache. No cache flush, network, TLS, browser, HTTP rate limits, competing writer, live consensus, key loading, disk power loss or private-room path was measured. Shared-host contention can change timings; the 1,000-to-10,000 activity projection was too optimistic.

## Current limits and next work

Native commands without `--replay-profile` replay from pinned genesis on every invocation and refuse after 4,096 bundles or 30 seconds. The separately implemented authenticated native replay profile preserves verified application state and permits bounded incremental catch-up. These benchmarks do not measure that new checkpoint path; its correctness tests are not substituted for a performance result. See the [native replay workflow](../crates/vhalla-cli/README.md#restartable-certified-replay).

The v1 activity store supports lifetime histories beyond 4,096 within its immutable configured event/byte budgets; it opens fixed metadata and reads pages of at most 64. The separate v2 continuity store caps unreclaimed temporary ancestors at 4,096 across at most 64 author slots and 32 MiB. Staging uses 32-event pages; finalization accepts at most 32 inline ancestors plus a current-policy terminal and streams the complete staged prefix. Its immutable lease is 60–86,400 seconds. Permanent history and temporary staging have different bounds. Increasing that staging cap does not implement bounded incremental finalization.

Writer-side journal recovery separately enumerates retained markers and bundle IDs with O(history) work and returned non-tip IDs; the read-only replay measurement excludes that startup path.

## Prospective sync reduction

The steady-state v1 activity append performs 14 `sync_all` calls: six file and eight directory barriers. Creating the first author directory adds two directory barriers. A freshly written intent is synced, renamed and directory-synced; `finish_intent` immediately re-syncs the same intent and directory because it also serves crash recovery.

The smallest proposed change is an internal proof token or split helper allowing only an already-durable fresh intent to omit those two repeated barriers. Recovery must retain them. Keep the file format, all checks, record/index/head barriers and final cleanup-before-ack contract. Crash tests must prove the token is never available before completed publication and every interrupted point still recovers exactly once. No sync reduction or speedup is implemented or measured here.

A bounded same-room batch could share intent, directory and final-head barriers. It needs a versioned bounded batch intent, exact current registry basis under the integration lock, per-full-key author bases checked across all offered events, all immutable records/indices durable before heads, exact retry after policy revocation, and bounded prefix recovery. Acknowledgements must wait for the complete transaction. Batch waiting must be bounded and cannot wait for work that itself depends on an acknowledgement. This is a separate recovery/format design, not permission to delete sync calls.
