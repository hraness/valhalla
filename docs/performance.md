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

The v1 activity store supports lifetime histories beyond 4,096 within its immutable configured event/byte budgets; it opens fixed metadata and reads pages of at most 64. The separate v2 continuity store caps unreclaimed temporary ancestors at 4,096 across at most 64 author slots and 32 MiB. Staging uses 32-event pages; finalization accepts at most 32 inline ancestors plus a current-policy terminal and streams the complete staged prefix. Its immutable lease is 60–86,400 seconds. Permanent history and temporary staging have different bounds. Increasing that staging cap does not implement bounded incremental finalization; the implemented mechanism instead advances a farther fixed target through ordered intermediate terminal admissions within the existing cap.

Writer-side journal recovery separately enumerates retained markers and bundle IDs with O(history) work and returned non-tip IDs; the read-only replay measurement excludes that startup path.

## Prospective sync reduction

The steady-state v1 activity append performs 14 `sync_all` calls: six file and eight directory barriers. Creating the first author directory adds two directory barriers. A freshly written intent is synced, renamed and directory-synced; `finish_intent` immediately re-syncs the same intent and directory because it also serves crash recovery.

The smallest proposed change is an internal proof token or split helper allowing only an already-durable fresh intent to omit those two repeated barriers. Recovery must retain them. Keep the file format, all checks, record/index/head barriers and final cleanup-before-ack contract. Crash tests must prove the token is never available before completed publication and every interrupted point still recovers exactly once. No sync reduction or speedup is implemented or measured here.

A bounded same-room batch could share intent, directory and final-head barriers. It needs a versioned bounded batch intent, exact current registry basis under the integration lock, per-full-key author bases checked across all offered events, all immutable records/indices durable before heads, exact retry after policy revocation, and bounded prefix recovery. Acknowledgements must wait for the complete transaction. Batch waiting must be bounded and cannot wait for work that itself depends on an acknowledgement. This is a separate recovery/format design, not permission to delete sync calls.

# Private steel thread baseline

These baseline measurements were recorded on the unmodified tree before the barrier-reduction changes below. They are synthetic local evidence, not a production capacity recommendation.

The [steel-thread example](../crates/vhalla-private-native/examples/steel_thread_bench.rs) runs two in-process cooperating-host drivers against one loopback TLS relay on `127.0.0.1:0` under fresh synthetic homes (`/private/tmp/valhalla-perf-*`). It exercises the production kernel store, delivery store, scan directory, relay and TLS service through a separate application-only measurement loop. It stamps six points per message (A queue, A relay enqueue, relay retained, B applied, B acceptance retained, A acceptance recorded). The installed host, its ports and its launchd labels are never touched. Runs were scheduled through the same heavy compute wrapper as the sections above, on the same hardware and toolchain, with the shared target directory and a 60-second passive idle phase inside each process.

The fixture's `production` cadence label is retained for baseline comparability:
one job, an eight-item page and a fixed five-second poll. It does not track the
current native controller's eight-job ticks, 64-item pages, adaptive idle polling,
control merge or restored-marker verification. These results do not measure
current real-process MCP or browser queue-to-acceptance performance.

```text
CARGO_TARGET_DIR=/private/tmp/valhalla-steel-20260922/.build \
  cargo build --release --locked -p vhalla-private-native \
  --example steel_thread_bench --features relay-tls
$BUILD/release/examples/steel_thread_bench /private/tmp/valhalla-perf-base-100 100
$BUILD/release/examples/steel_thread_bench /private/tmp/valhalla-perf-base-1000 1000
```

A 10,000-message run is refused by the harness: two relay items per acknowledged message would exceed the fixed 4,096-item mailbox capacity. `/usr/bin/time -lp` was not wrapped around these runs, so process maximum RSS is unavailable; retained-home file counts and bytes are reported instead. F_FULLFSYNC counts are estimated from the reviewed barrier ledger (approximately 56 per acknowledged message in this cadence), not measured with kernel counters.

| Measurement | 100 messages | 1,000 messages |
|---|---:|---:|
| Calibrated file F_FULLFSYNC p50 |4.740ms (32 samples)|3.985ms (32 samples)|
| Calibrated directory F_FULLFSYNC p50 |4.669ms|0.005ms (clean directory)|
| Relay + device + join setup |0.821s|0.382s|
| Acknowledged-message wall time |218.017s (2.18s/message)|1,710.696s (1.71s/message)|
| First queue to last acceptance |157.954s|1,650.495s|
| `queue_kernel_send` p50 / p95 / p99 |30.156 /91.063 /140.900ms|48.419 /110.580 /290.835ms|
| `queue_to_relay_retained` p50 / p95 / p99 |2,423 /5,210 /7,980ms|2,438 /5,042 /6,518ms|
| `relay_retained_to_b_applied` p50 / p95 / p99 |2,807 /5,290 /5,863ms|3,435 /5,862 /6,830ms|
| `b_applied_to_acceptance_retained` p50 / p95 / p99 |2,957 /4,600 /5,353ms|3,261 /5,949 /7,226ms|
| `acceptance_retained_to_a_recorded` p50 / p95 / p99 |3,319 /5,562 /5,894ms|3,192 /5,812 /6,358ms|
| Round-trip p50 / p95 / p99 |11.257 /16.854 /17.741s|11.550 /17.228 /19.341s|
| Passive idle phase wall |60.000s|60.000s|
| Relay retained files / logical / allocated |2 /200,704 /200,704B|2 /1,662,976 /2,162,688B|
| Driver A files / logical / allocated |408 /508,871 /2,011,136B|4,008 /4,502,876 /19,542,016B|
| Driver B files / logical / allocated |408 /495,983 /1,998,848B|4,008 /4,464,108 /19,542,016B|

Per-driver production counters for the 1,000 run: A made 1,209 ticks, 1,000 puts, 292 relay pages, 1,000 enqueues, 1,000 receives, 2,000 applied markers and 1,207 scan reopens; B made 1,151 ticks, 1,001 puts, 291 pages, 2,000 enqueues, 1,000 receives, 1,000 acceptances and 1,999 applied markers. Idle phases made only ticks, page polls, outbox reads and scan reopens (B also one deferred applied marker).

The multi-second per-stage latencies include the fixture cadence's poll intervals, not only fsync cost; the stage medians are the useful comparison points between baseline and optimized trees, not the wall totals. The 1,000-run directory calibration reads ~5µs because repeated directory syncs of an unchanged directory are cheap — directory barriers cost ~4.7ms only when a new entry must be flushed, which is exactly the case the optimized paths remove.

## Optimizations landed and after-measurements

The landed barrier reductions, per the reviewed ledger (counts are `F_FULLFSYNC` equivalents; the private kernel store gets three inside every SQLite `COMMIT` under `synchronous=EXTRA` + `fullfsync=ON` — journal, database pages and the journal-unlink directory sync):

| Path | Before | After | Removed |
|---|---:|---:|---:|
| Private kernel store `publish` |5 (3 COMMIT-internal + 2 code-level)|3|2 code-level re-syncs (E-14)|
| Journal commit, fresh bundle, warm layout |10|6|3 proven-layout + 1 fresh-bundle re-sync (E-15)|
| Journal commit, retained bundle |11|7|same 4; bundle re-sync retained|
| Activity append, fresh intent |14 (6 file + 8 dir)|12 (5 file + 7 dir)|2 proven intent re-syncs (E-1)|
| Activity append, retained/recovery |14|14|0 — conservative re-sync retained|
| `read_page` signature verifications |2 per record|1 per record|CPU, not a barrier (E-18)|
| Steel thread per acknowledged message |~56 (estimated)|~48 (estimated)|~8 via 4 kernel publishes × 2 (E-14)|

The E-2 spike under [`prototypes/activity-append-log`](../prototypes/activity-append-log/README.md) measures the proposed append-log format at exactly 2 barriers per append (log sync, then head-slot sync) — versus 12 in the shipped store — with the retained-intent, torn-tail and torn-slot recovery cases covered by 8 tests. Production adoption stays deferred for the reasons that README lists (signed-record framing, bounded open, author-table bound, bounded-history compaction, v1 migration and the full crash matrix).

After-run results, same commands, same host class, optimized tree (`valhalla-perf-opt-*`):

| Steel thread | 100 baseline | 100 after | 1,000 baseline | 1,000 after |
|---|---:|---:|---:|---:|
| Calibrated file F_FULLFSYNC p50 |4.740ms|4.637ms|3.985ms|3.931ms|
| Acknowledged-message wall |218.017s|215.828s|1,710.696s|1,649.404s (−3.6%)|
| First queue to last acceptance |157.954s|155.746s|1,650.495s|1,589.034s (−3.7%)|
| Round-trip p50 / p95 / p99 |11.257 /16.854 /17.741s|10.968 /17.600 /18.372s|11.550 /17.228 /19.341s|11.574 /17.480 /19.720s|
| Driver A files / logical / allocated |408 /508,871 /2,011,136B|408 /508,871 /2,068,480B|4,008 /4,502,876 /19,542,016B|4,008 /4,486,492 /19,542,016B|
| Driver B files / logical / allocated |408 /495,983 /1,998,848B|408 /495,983 /2,056,192B|4,008 /4,464,108 /19,542,016B|4,008 /4,468,204 /19,542,016B|

| Activity / replay (1,000 ops) | Baseline | After (first run) | After (clean re-run) |
|---|---:|---:|---:|
| Activity sign + verify + durable append |64.671s|94.964s (contended)|62.099s (−4.0%)|
| Activity append p50 / p95 / p99 |64.885 /78.905 /93.976ms|73.117 /226.936 /361.020ms|60.621 /83.847 /104.798ms|
| Canonical sign/decode/verify only |0.155s|0.252s|0.143s|
| Journal generate/sign/verify + fsync |52.806s|47.742s|—|
| Certified disk replay from genesis |183.103ms|168.455ms|—|
| Simulated native replay budget |complete, 173.707ms|complete, 150.735ms|—|
| Full verified activity pagination |249.628ms|245.090ms|273.325ms|
| 100 exact retained retries |64.430ms|46.592ms|61.941ms|
| 20 reopen + verified author-head reads |18.828ms|16.860ms|26.743ms|
| Activity allocated regular-file bytes |8,204,288|8,204,288 (2,004 files)|8,204,288 (2,004 files)|
| Replay allocated regular-file bytes |8,196,096|8,196,096 (2,002 files)|—|

The first activity after-run ran inside a contended window: its p95 roughly tripled while p50 rose only ~13%, and the same batch's later replay and steel runs show ~4.6ms barrier calibration — a signature of external disk pressure during that run, not of extra barriers (the fresh path is statically 12 `sync_all` calls, pinned by tests). The clean re-run confirms: append wall −4.0% and p50 −6.6% while paying ~9% *more* per barrier than the baseline run (60.6ms for 12 barriers ≈ 5.05ms each versus 64.9ms for 14 ≈ 4.64ms each) — removing two barriers is what kept the number ahead despite the dearer barrier unit price. Pagination, exact-retry and reopen-read deltas of a few milliseconds are run-to-run noise on this shared host.

Steel-100 after-run counters: A made 132 ticks / 100 puts / 29 pages / 100 enqueues / 100 receives / 232 outbox reads / 131 scan reopens; B made 128 ticks / 100 puts / 29 pages / 200 enqueues / 100 receives / 100 acceptances / 128 scan reopens. Steel-1,000 after-run counters: A 1,224 ticks / 1,000 puts / 279 pages / 1,000 enqueues / 1,000 receives / 2,000 applied markers / 2,224 outbox reads / 1,223 scan reopens; B 1,204 ticks / 1,000 puts / 279 pages / 2,000 enqueues / 1,000 receives / 1,000 acceptances / 2,000 applied markers / 1,204 scan reopens.

Two earlier steel-1,000 after-runs aborted on a `ScanFailure::Timeout` from the scan guard's 90-second absolute budget under heavy host contention (~800 and ~400 acknowledgements; 447k involuntary context switches). Both preserved their synthetic homes without `metrics.tsv`. The harness treated that transient timeout as fatal; the fix (commit `b88f31c`) ends the tick and retries, matching the production host loop and the timeout policy `scan_page_until` already used. The completed 1,000 run above used the fixed harness; it changes only the failure path, not the measured steady-state stages.

Wall-time deltas are cadence-dominated: the harness polls on its historical tick boundaries, so removing ~8 barriers (~37ms) per acknowledged message moves the 100-message wall only ~1% — matching the observed 218.0→215.8s. The useful signals are the barrier ledger (static), the journal/activity append phase times (barrier-dominated), and the spike's measured 2-barrier append (p50 9.96ms at ~4.9ms/barrier on this host, 64-record verified page read in 276µs).
