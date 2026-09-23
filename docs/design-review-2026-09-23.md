# Design and engineering continuation, 23 September 2026

## Baseline and scope

This review continues from origin/main `0eee3b6`, which is release v0.2.1
(installed on the development Mac on 2026-09-22), on branch
`claude/steel-thread-20260922` in the integration worktree. The baseline was
clean. The subject is the chosen first workflow, the private steel thread:
agent A, MCP `agent-serve`, private room, local TLS relay mailbox, agent B or
browser, acceptance receipt back to A. The goal of the program is to make that
thread performant, robust and resilient; this document records what six
read-only review lanes found on 2026-09-22 and 2026-09-23 and what the repair
continuation is expected to do about it.

Six lanes read source and tests, not documentation, and ran no cargo command
(a shared target directory was locked by a warm-up build). Every claim below
is from code unless it is marked unverified; timing figures are model
estimates calibrated against the two measurements in `docs/performance.md`,
not new measurements.

| Lane | Scope read | Findings file |
| --- | --- | --- |
| A relay/host | `vhalla-private-native/src/relay/{mod,tls,net,http}`, `vhalla-cli/src/{private_host,private_gateway,launchd}`, delivery store | `review-A-relay-host.md` |
| B agent/MCP | `vhalla-private-native/src/{agent,client/agent_rpc,grant}`, `vhalla-cli/src/private_rooms/{agent,agent_delivery,agent_setup}` | `review-B-agent-mcp.md` |
| C kernel | `vhalla-private-kernel`, `vhalla-private-protocol`, `vhalla-custody`, native kernel store | `review-C-kernel.md` |
| D browser | `browser/src/private/**`, `vhalla-browser-storage`, browser harnesses, gateway HTTP path | `review-D-browser.md` |
| E performance | barrier ledgers for activity store, mailbox, scan, delivery, kernel store, journal, replay | `review-E-performance.md` |
| F steel thread | the operator and two-agent path as installed, receipts and one-off scripts | `review-F-steel-thread.md` |

Not covered by any lane (aggregate of the six "not reached" lists):

- `relay/http/tests.rs`, `relay/delivery/tests.rs`, `vhalla-private-relay/src/wire_tests.rs` bodies; `agent.rs` frame loop beyond tick cadence; `applied.rs::validate` status sources.
- `relay/delivery.rs` beyond `enqueue`/`tick`; `ScanDirectory::{publish_item,read,publish_cursor}` internals; `files.rs::write`; kernel `publish_received`/`publish` tail; `tests/private_agent_delivery.rs:581-680`; actual Codex 0.155.1 and Devin wire behaviour.
- `tests/{contact,recovery,confidential}.rs` bodies; `vhalla-custody/src/tests.rs`; `vhalla-private-protocol/src/tests.rs`; the native store's SQLite schema, `prepare`, `inventory` and recovery-on-open; OpenMLS internals beyond cited config/storage lines.
- `vhalla-browser-storage/src/{outbox,history,native}` public-room paths; `browser/src/network/*`; `browser/src/ui.rs` beyond worker lifecycle; the non-delivery browser harnesses beyond port usage; `browser-vault` backup and key derivation; Chromium Local Network Access behaviour; packaged WASM sizes.
- `room-activity-store/src/continuity/**`; social-store and rooms-store recovery matrices; Malachite WAL internals; `arc-malachitebft-signing-ed25519` key exposure; the desktop path.
- `relay/tls.rs` service internals as seen from the CLI; Devin `mcp list` spawn behaviour; Tailcat v0.7.0 reconnect beyond receipts.

## Architectural assessment

**Verified sound.** The six lanes independently confirmed the boundaries the
2026-09-22 review chose to retain:

- Authority: a control applies only when `check_control` pins the owner device, parent floor, epochs and commit digest and the MLS commit sender is the owner leaf (`membership.rs:587-591,682-698`; `transport.rs:115-123`); K1 and K2 from the previous review are present with no grant-only fallback (`succession.rs:101,171-176`; `records.rs:461-476`; `membership.rs:315-319,360-368`). Archives cannot go live (`frame.rs:173-179`; `destination.rs:428-434`).
- Transactional publication: state CAS plus at most three immutable records in one store call, released only after readback (`engine.rs:108-148`; native `private_rooms.rs:412-538` in one `BEGIN IMMEDIATE`). Kernel `receive` is idempotent on the exact wire (`engine.rs:223-239`; `messages.rs:90-93`), so every crash window in the driver and the browser replays safely.
- Durability ordering: mailbox `journal_mode=DELETE, synchronous=FULL` with explicit barriers (`relay/mod.rs:389-401`); scan items are tmp, fsync, rename, directory fsync and the cursor follows the item (`net.rs:352-378,673-723`); delivery intent is committed and synced before the transport call and the outcome after (`delivery.rs:552-604`); `applied::publish` is pending-append, fsync, `renameat NOREPLACE`, directory fsync, readback (`applied.rs:98-144`); browser writes are `durability: "strict"` and refused when the engine ignores the option (`durability.rs:20-47`).
- Authentication order: relay client pins CA, exact name and TLS 1.3, ALPN carries the namespace (`tls.rs:141-151`); the server checks ALPN, frame length, constant-time token, permission, window, then the operation (`service.rs:402-462`). Gateway requires exact `Host`, exact `Origin`, constant-time bearer, namespace header, refuses `OPTIONS` (`http.rs:41-53,435-477`). Epoch and roster changes revoke a grant before any queued reply is written (`agent_rpc.rs:122-135`; `agent.rs:167-244`).
- Idempotency and quotas: exact relay retries are keyed by digest and never double-charged, and are accepted when the quota is full (`service.rs:506-519`; `mod.rs:279-315`); duplicate `enqueue` returns the prior status and a new body under an old operation is `Conflict` (`delivery.rs:409-416`; `engine.rs:187-208`).
- No panic reachable from input was found in the kernel, protocol, relay codec, RPC argument parsing or gateway header parsing.

**Weakness 1: permanent wedges.** The lanes converged on one shape of defect
from four directions: a single bad item, one miscounted budget or one ordinary
outage turns a recoverable condition into a terminal one, and the product owns
no recovery command. A stale-epoch application message is an undifferentiated
`Error::Scope` that latches the kernel (C1); the native driver maps any
`receive` error to `REFUSED`, ends the grant, writes no marker and retries the
same position on every relaunch (F1); the browser worker does the same and
reports "Reload required" forever (D2). An out-of-range `private_outbox_status`
argument latches the kernel and the server exits without writing the refusal
(B1). A relay outage longer than the retry budget stops every job with no
re-arm (A1); ten transient browser failures set a `stopped` flag nothing clears
(D3); the browser charges the theoretical 4 MiB maximum per page fetch, so
delivery dies after 255 syncs (D1). A poll counter of 4096 silently stops
inbound scanning after about 5.7 hours of a 24 hour grant (A2, B3). Every
retained capacity is finite, never pruned and has no rotation path, so a busy
room bricks its own delivery after roughly 1000 exchanges (A3, F3). The 365 day
host leaf has no renewal command and the LaunchAgent crash-loops into
`/dev/null` when it expires (A4, F12). The repair contract is the same in every
lane: typed refusals instead of one variant, latch only across the write
barrier, a durable skip or quarantine marker that the operator can inspect, and
a product command for every re-arm.

**Weakness 2: barrier cost.** On Apple targets `File::sync_all` and
`sync_data` compile to `fcntl(F_FULLFSYNC)`, a whole-device flush of about 4.6
ms regardless of bytes (lane E, verified against the Rust 1.98.1 standard
library). Every store in the repository uses `sync_all`; none calls plain
`fsync`. The model reproduces both published measurements with that one
constant (14 barriers for the 64.9 ms activity append; 10 for the 52.8 ms
journal commit). One acknowledged private message A to B to A costs about 56
barriers and 30 plain fsyncs across kernel publishes (6 each), delivery commits
(2 each, three per attempt), the relay PUT (2 plus 3), scan publication (4 per
pulled item) and `applied` markers (E-6, E-9, E-14, A7). The wall clock is set
by pollers rather than barriers today (1 job per 1 s tick, 8 items per 5 s
poll: p50 about 5 to 6 s per round trip, 1 message/s outbound), but the idle
loop still commits the delivery clock and re-lists the whole scan directory
every second (A5, E-12, F10), and the relay and delivery SQLite files run
`synchronous=FULL` without `PRAGMA fullfsync`, which is both weaker under power
loss and two flushes more expensive than necessary (E-7). Restart replays the
entire outbox and applied history with a durable commit per record before any
inbound item is processed (A6, B6, E-6, F11).

**Weakness 3: operator and agent ergonomics.** The installed steel thread has
twenty steps; nine are manual or driven by one-off Python scripts, including
hand-authored fifteen-field delivery profiles, hand-written gateway and Tailcat
plists, five `-c` overrides per Codex launch, and never-used receipt paths for
every grant renewal (lane F, Part 1). The default grant lifetime of 900 s makes
a two-agent exchange fail by default when the humans are slower than fifteen
minutes (F2); acceptance visibility is poll-only, charged against the read
budget and bounded by the sender's process lifetime (B2, F9); receipts land in
the agent-visible inbox as binary rows (F5); the host mints exactly two
credentials for a thread that needs three (F4); nothing gives an operator a
read-only view of delivery state (F14) or a health probe that does not shell
out to `lsof` (F6). The previous review's third weakness, evidence
maintenance, recurs as F13 and E-13: docs describe intent that the code does
not implement.

## Findings and repair lanes

Severity: P0 data loss, security or authority break; P1 wrong behaviour or
unrecoverable state in a plausible scenario; P2 robustness, performance or
resilience gap; P3 cleanliness. Status is filled by the integration owner.

| ID | Sev | Finding | Repair lane | Status |
| --- | --- | --- | --- | --- |
| A1 | P1 | Jobs whose transport failures exhaust `max_attempts` become `Stopped` and nothing re-arms them (`relay/delivery.rs:528-575`) | relay/host | fixed |
| A2 | P1 | `poll_attempts < 4096` is never reset, so inbound scanning stops after about 5.7 h of a long grant (`agent_delivery.rs:325-345`) | agent/MCP | fixed |
| A3 | P1 | Mailbox, credential and job capacities are finite, never pruned and have no rotation path (`config.rs:247-250`; `private_host.rs:133-139`; `delivery.rs:432-451`) | relay/host | fixed |
| A4 | P1 | The 365 day TLS leaf has no renewal command; `serve` refuses after expiry and launchd loops silently (`config.rs:166,183`; `private_host.rs:153-158`; `launchd.rs:30-37`) | relay/host | fixed |
| A5 | P2 | Idle tick commits the clock and re-opens the scan with a directory sync and O(items) opens (`delivery.rs:493-495`; `net.rs:476-650`) | agent/MCP, `net.rs` part relay/host | fixed |
| A6 | P2 | Every launch replays the whole outbox with one durable commit per duplicate `enqueue` before any scan (`agent_delivery.rs:262-315`; `delivery.rs:409-416`) | agent/MCP | fixed |
| A7 | P2 | One PUT performs four explicit F_FULLFSYNC, two inside the open transaction, under the service mutex (`tls/service.rs:500-537`; `relay/mod.rs:327-393`) | relay/host | fixed |
| A8 | P2 | PAGE reserves 4 MiB of window budget regardless of size, capping a credential at 8 PAGE/s (`tls/service.rs:445-451`) | relay/host | fixed |
| A9 | P2 | Pre-authentication sockets hold a worker for the full 10 s request timeout; 16 idle sockets deny service (`service.rs:314-316,391-405`) | relay/host | fixed |
| A10 | P2 | Host failures are invisible: no log, no bind retry, `status` cannot distinguish a crash loop from health (`launchd.rs:36-37`; `private_host.rs:97,151-161`) | relay/host | fixed |
| A11 | P2 | Delivery store refuses on any wall-clock regression, ending the grant on every launch until time catches up (`delivery.rs:365-380`) | agent/MCP | fixed |
| A12 | P2 | Gateway has no stop flag, no supervision and no drain (`private_gateway.rs:219-221`; `relay_tls.rs:182`) | relay/host | fixed |
| A13 | P3 | Gateway over-capacity drops the socket instead of replying 503 with `Retry-After` (`http.rs:264-279`) | relay/host | fixed |
| A14 | P3 | PAGE decodes and re-hashes up to 17 MiB under the mutex to send at most 4 MiB (`relay/mod.rs:349-370`; `codec.rs:231-253`) | relay/host | fixed |
| A15 | P3 | Per-connection overheads: 10 to 20 ms accept park, thread per connection, handshake per request, byte-per-read headers (`service.rs:295-334`; `http.rs:293-376`) | relay/host | fixed |
| A16 | P3 | Full-table `COUNT/SUM` scans on every PUT and no index on `tls_charges.key_id` (`relay/mod.rs:300-307`; `service.rs:99,515`) | relay/host | fixed |
| B1 | P1 | Out-of-range `private_outbox_status` or a conflicting `private_queue` latches the kernel and the server exits without writing the refusal (`agent_rpc.rs:122-135,388-395`; `agent.rs:421-433,458-463`; `engine.rs:324-344`) | agent/MCP | fixed |
| B2 | P2 | `private_outbox_status` charges 512 KiB of `read_bytes` per call regardless of `limit`; the default grant allows 64 polls (`agent.rs:426,447-450`) | agent/MCP | fixed |
| B3 | P2 | Fixed per-launch counters (4096 requests, 4096 polls) end or silently degrade a 24 h grant with no explanation (`agent_rpc.rs:146-153`; `agent_delivery.rs:335-337`) | agent/MCP | fixed |
| B4 | P2 | A blank line, more than 16 pipelined frames or any `notifications/cancelled` terminates the process and burns the grant (`agent.rs:121-130,148-150`; `agent_rpc.rs:186-189`) | agent/MCP | fixed |
| B5 | P2 | The claim is consumed before the first stdin read, so any Codex probe or a second window burns the grant (`agent.rs:55-73`; `grant.rs:223-238`) | agent/MCP | fixed |
| B6 | P2 | Linear replay of outbox and applied history per launch; O(N) `positions()` per tick; `outbox_head > 4096` refuses forever (`agent_delivery.rs:260-361,278`) | agent/MCP | fixed |
| B7 | P2 | Inbound latency floor: one 8-item page per 5 s, 30 s after any transient error, fresh TLS connection per exchange (`agent_delivery.rs:335-347`) | agent/MCP | fixed |
| B8 | P2 | A wall-clock step backwards of 1 s or more permanently ends the launch (`agent_rpc.rs:125`) | agent/MCP | fixed |
| B9 | P3 | Strict parameter whitelists reject the spec-legal `cursor` on `tools/list` and `ping` (`agent_rpc.rs:198,257`) | agent/MCP | fixed |
| B10 | P3 | A refused TCP connect before any byte is sent is reported as `uncertain` rather than definite non-submission (`relay/delivery.rs:589-600`) | agent/MCP | fixed |
| C1 | P1 | A stale-epoch application message is an undifferentiated `Error::Scope` that latches the kernel and wedges the driver loop (`engine/messages.rs:148-152`; `engine.rs:82-99`; `agent_delivery.rs:397-400`) | kernel, driver marker agent/MCP | fixed |
| C2 | P2 | Every deterministic refusal (`Scope`, `Policy`, `Time`, `Mls`, `Conflict`, `Bounds`) forces a full reopen although nothing was written (`engine.rs:82-99`) | kernel | fixed |
| C3 | P2 | No durable sender-side acceptance status or ciphertext-hash to outbox index in the kernel; native verification lives in process memory, the browser does not verify (`acceptance.rs:72-182`; `agent_rpc/delivery.rs:17-95`) | kernel | fixed |
| C4 | P2 | Sender-ratchet window (4 late, 32 ahead) turns a delivery gap into an unclassified `Error::Mls` (`drafts.rs:105`; `membership.rs:400`; `messages.rs:153-155`) | kernel | fixed |
| C5 | P2 | Two full image decodes with full signature re-verification and one whole-image rewrite per message; `check_files` three times per publish (`engine.rs:82-148`; `model.rs:396-520`; `private_rooms.rs:421-538`) | kernel | fixed |
| C6 | P2 | Caller clock is retained monotonically with no forward bound; one far-future `now` bricks the store until real time catches up (`model.rs:304-311`) | kernel | fixed |
| C7 | P3 | `ArchiveView` re-decodes the entire archived state per page (`recovery/destination.rs:487-504,615-637`) | kernel | fixed |
| C8 | P3 | `docs/private-rooms.md:337` names format versions v4/v3 where code is v5/v4/v3 (`model.rs:17`; `packets.rs:52`; `contact.rs:45`) | kernel | fixed |
| C9 | P3 | No Hegel stateful tests in the kernel crate; the C1/C3/C4 interleavings are exactly what such a model would pin (`vhalla-private-kernel/Cargo.toml`) | kernel | fixed |
| C10 | P3 | MLS provider secrets in `State.records` and `Working` are not zeroized on drop (`model.rs:40`) | kernel | fixed |
| C11 | P3 | Permanent limits worth a product decision: 16 successions forever, expired offers reclaimed only on new offer, inbox growth undocumented (`model.rs:15`; `contact.rs:68-70`; `packets.rs:295-304`) | kernel | fixed |
| D1 | P1 | Each page fetch reserves the 4 MiB maximum against the 1 GiB lifetime budget; delivery stops after 255 syncs with no reset (`delivery.rs:197-201,319-323`; `delivery_model.rs:97-108`) | browser | fixed |
| D2 | P1 | A deterministic kernel refusal on one staged record (epoch race, phase, expiry, foreign item) wedges browser delivery permanently (`delivery.rs:256-263,361-365`; `worker.rs:162-165`) | browser | fixed |
| D3 | P1 | Ten consecutive transient failures make `stopped` permanent; with an unsupervised gateway this is an ordinary outage (`delivery_model.rs:97-106`) | browser | fixed |
| D4 | P2 | Relay-delivered `ContactRequest`/`ContactInvitation` items are silently consumed with no retained evidence (`delivery.rs:279-288,392-398`) | browser | fixed |
| D5 | P2 | Wall-clock regression locks browser delivery out until the clock catches up (`delivery.rs:123`; `delivery_model.rs:90-92`) | browser | fixed |
| D6 | P2 | Gateway admission budget and connection slots are charged before any authentication; 8 silent sockets starve the real tab (`http.rs:266-279,344-376`) | relay/host | fixed |
| D7 | P2 | Gateway is fail-stop on any handler panic and has no supervisor (`http.rs:254-311`; `private_gateway.rs:210-215`) | relay/host | fixed |
| D8 | P2 | Every browser kernel operation round-trips the full image; a 4-record sync is about 25 image passes and 8 strict transactions (`browser/private_rooms.rs:286-317`; `engine.rs:81-139`) | browser, kernel cache from C5 | fixed |
| D9 | P2 | Delivery harness hard-codes ports 8790 and 19473 with no collision check and a README that misdescribes them (`qualify_private_delivery.mjs:155-395`) | browser | fixed |
| D10 | P3 | `Session::revalidate` opens a fresh IndexedDB connection on every call, about 12 per sync (`session.rs:167-176,255-262`) | browser | fixed |
| D11 | P3 | Gateway reads headers one byte per `read` with a `set_read_timeout` per byte (`http.rs:344-376`) | relay/host | fixed |
| D12 | P3 | Capability copies in JS heap are never zeroed; profile file permissions are undocumented (`panel.rs:272-289`; `ui/private.rs:318-326`) | browser | fixed |
| D13 | P3 | Harness assertions depend on unversioned byte offsets and the 2 s backoff constant (`qualify_private_delivery.mjs:276-283,330-382`) | browser | fixed |
| D14 | P3 | The previous B2 repair is present but has no truncated-archive DOM or harness pin (`panel/actions.rs:1110-1131,1319`) | browser | fixed |
| E-1 | P2 | Activity store re-syncs a freshly durable intent: 14 barriers where 12 suffice (`activity-store/src/unix.rs:379-391,484-485`) | performance | fixed |
| E-2 | P2 | Single fixed-name append log with slotted heads would take the activity append from 14 to 2 barriers (format change) | performance | spiked: prototypes/activity-append-log measures 2 barriers/append; production adoption deferred per its README |
| E-3 | P2 | Bounded group commit after E-2 (2 barriers per group) | performance | deferred: bounded group commit follows E-2 adoption, which stays a format decision |
| E-4 | P3 | Seven Ed25519 verifies and about 230 metadata syscalls per append; two verifies per paged record (`unix.rs:430-478,641-676`) | performance | fixed |
| E-5 | P3 | `examples/performance.rs:171` counts `author_head` inside append timing | performance | fixed: per-phase timing split recorded in docs/performance.md |
| E-6 | P1 | Delivery driver: 1 job per 1 s tick, 8 items per 5 s poll, `applied` restarts at 0 (n/8 s stall after relaunch), O(n) `positions()` twice per tick (`agent_delivery.rs:261-361`) | agent/MCP | fixed |
| E-7 | P2 | Relay and delivery SQLite run `synchronous=FULL` without `fullfsync` then add two code-level barriers: weaker under power loss and two flushes too many (`relay/mod.rs:432-437`; `delivery.rs:227-231`) | relay/host, delivery store agent/MCP | fixed |
| E-8 | P2 | Mailbox mutex is held across device flushes, so PAGE waits behind PUT; about 80 to 100 req/s ceiling (`tls/service.rs:410-486`) | relay/host | fixed |
| E-9 | P2 | Four F_FULLFSYNC per pulled scan item; a page-level barrier group would make it 2 per page (`net.rs:355-378,673-723`) | relay/host | fixed |
| E-10 | P3 | Two O(n) scans per PUT (same evidence as A16) | relay/host | fixed |
| E-11 | P3 | Thread and TLS handshake per request, no resumption or keep-alive (`service.rs:329-334`; `tls.rs:161-180`) | relay/host | fixed |
| E-12 | P2 | Idle `agent-serve` performs 2 F_FULLFSYNC, 3 fsync and one image decrypt per second, and a handshake per 5 s, forever (`delivery.rs:524-525`; `agent_delivery.rs:273-277`) | agent/MCP | fixed |
| E-13 | P3 | `docs/performance.md` never states that `sync_all` is F_FULLFSYNC on Darwin; the 14-barrier and 52.8 ms figures are fully explained by it | performance | fixed: docs/performance.md now states sync_all is F_FULLFSYNC on Darwin and keeps a barrier ledger |
| E-14 | P3 | Kernel native store: `check_files` three times and code-level syncs on top of `synchronous=EXTRA`: 6 barriers where 4 suffice (`private_rooms.rs:436,492-550,861`) | kernel | fixed |
| E-15 | P2 | Journal `lock()` re-syncs two directories per commit and `sync_bundle` re-flushes an already-synced inode: 4 of 10 barriers redundant (`journal/src/lib.rs:523-538,1059`) | performance | fixed |
| E-16 | P2 | One decided value runs three independent two-phase protocols, about 29 barriers; stores could checkpoint periodically (`rooms-consensus/src/lib.rs:1250-1295`) | performance | deferred: consensus store checkpointing is a separate recovery-format change |
| E-17 | info | Five WAL flushes per height come from Malachite flush-before-publish; leave as is | performance | closed: left as is per the finding itself |
| E-18 | P3 | Certified replay is about 90 percent signature verification; per-page batch verification with per-signature fallback is about 1.7x (`public-client/src/lib.rs:167-236`; `cert.rs:139-185`) | performance | fixed |
| F1 | P1 | Any undecryptable relay item bricks every native driver in the namespace: no marker, no advance, re-fails on every relaunch (`agent_delivery.rs:399-403`; `agent.rs:245`) | agent/MCP, typed errors from kernel | fixed |
| F2 | P1 | Default 900 s grant, never-used receipt and output paths per renewal, grant path baked into MCP args: a two-agent exchange fails by default (`agent_setup.rs:29-31,74-83`; `agent_rpc.rs:122-136`) | journey | fixed |
| F3 | P1 | Installed host lifetime capacity is about 1000 messages for two agents sharing one credential; receipts halve it (`config.rs:246-251`; `private_host.rs:134`) | relay/host | fixed |
| F4 | P2 | `private-host init` mints exactly two credentials; the thread needs three and both agents share one quota and blast radius (`config.rs:20-39`) | relay/host | fixed |
| F5 | P2 | Acceptance receipts appear in `private_inbox` as binary rows and consume the read budget and follow window (`agent_rpc.rs:336-343`; `agent_delivery.rs:399-406`) | agent/MCP | fixed |
| F6 | P2 | The startup helper's `lsof -Fp` assertion could never pass; the receipt records the wrong cause; no product `status --probe` exists (`valhalla-local-start-20260922.py:290`) | relay/host | fixed |
| F7 | P2 | Fixed ports 8790, 19473 and 9473 collide between qualification and production and already forced an unreceipted gateway restart (same evidence as D9) | browser | fixed |
| F8 | P2 | Doc examples use hour-long device validity; enrollment expiry silently ends both agents with a generic `REFUSED` (`protocol/src/lib.rs:199`; `agent.rs:455`) | agent/MCP | fixed |
| F9 | P2 | Sender acceptance visibility is poll-only, budget-charged and bounded by the sender's process lifetime (same mechanism as B2) | agent/MCP | fixed |
| F10 | P2 | Driver hot loop performs O(items) file opens per second per agent (same evidence as A5, E-6) | agent/MCP | fixed |
| F11 | P2 | Restart cost grows with outbox length and blocks inbound processing (same evidence as A6, B6) | agent/MCP | fixed |
| F12 | P2 | No reboot, sleep/wake or logout qualification; the launchd crash loop is invisible (same evidence as A10) | relay/host | fixed |
| F13 | P3 | Doc/code disagreements: `--delivery`-only status fields, `status` health wording, missing `vhalla --version`, README build features, stale Tailcat receipt | journey | fixed: `vhalla --version`/`-V` reports crate version plus the compiled feature set; README documents the `experimental-private` build and feature check; `status` vs `status --probe` health wording landed with the relay lane; cli-agents.md documents the delivery-only outbox fields; Tailcat stays pinned at v0.7.0 matching the installed binary |
| F14 | P3 | No read-only `delivery-status` command; the only views need a live grant or hand-reading SQLite (`delivery.rs:468`) | journey | fixed: `vhalla private delivery-status ID STORE --config P --out FILE` reads the durable journal under its own lock with `--after`/`--limit` paging and no grant, network or plaintext exposure |

Lane B's B1 and lane F's F1 describe the same latch from two entry points
(read-side argument error versus inbound item); C1 and D2 describe the same
kernel refusal from two drivers. They are kept as separate rows because each
has its own repair and test.

Contradictions and boundary cases between lanes, recorded so the repair lanes
do not resolve them differently:

- Acceptance verification. The brief's reading of `docs/private-rooms.md:307`
  (receipts not verified against the sender's outbox) applies to the browser
  worker only. The native and CLI driver does verify each receipt
  (`agent_delivery.rs:406-439` through `MemberAcceptance::verify`,
  `acceptance.rs:72-113`, and `matches_original`), but the result is held in
  memory per launch and `originals` is rebuilt by paging the outbox from zero;
  the only durable evidence is the CLI's `applied/*.json`, outside the kernel.
  The precise truth is therefore: native verifies in memory per launch with
  no durable sender-side status, and the browser does not verify at all. C3
  is the kernel-side repair for both.
- Relay capacity outcome. A8 states that `STATUS_CAPACITY` is counted as a
  refusal attempt and so feeds A1 (`Stopped` after `max_attempts`); F3 states
  that `NetError::Capacity` leaves jobs `Pending` with backoff forever. Both
  read `delivery.rs:558-640`; the relay/host lane's Hegel test over
  `DeliveryStore::tick` with a tiny quota must pin which is true and the
  operator-facing status must name the exhausted quota either way.
- Crash ordering of the mailbox. Lane A verified the mailbox as crash-safe
  under process crash (atomic SQLite commit, then explicit barriers). Lane E-7
  observes that without `PRAGMA fullfsync` the rollback journal reaches only
  the drive cache, so under power loss between SQLite's commit and the
  code-level barrier a torn database is possible. Both are correct for their
  fault model; E-7 is the repair.
- Epoch check location. C1 cites `engine/messages.rs:148-152` (`process`)
  and D2 cites `messages.rs:118-121` for the `message.epoch() != state.epoch`
  refusal. The kernel lane resolves the exact site when adding the typed
  `StaleEpoch`/`FutureEpoch` variants.
- `Connect` classification. B10 asks that a refused connect be a definite
  non-submission; A1 asks that transport failures not spend the lifetime
  attempt budget. The two are compatible: `Connect` becomes definite pending
  and does not count toward `Stopped`; `Timeout` stays uncertain.

## Execution graph

1. **Review, complete.** Six read-only lanes on the shared baseline with a
   common brief; findings files retained in the session scratchpad and
   consolidated here.
2. **Six parallel repair and spike lanes on disjoint file ownership.**
   - Kernel: `crates/vhalla-private-kernel/**`, `crates/vhalla-private-protocol/**`,
     `crates/vhalla-private-native/src/private_rooms.rs` (native kernel store),
     `docs/private-rooms.md`. Typed refusal taxonomy, latch only across the
     write barrier, durable acceptance index, clock bound, decode cache,
     Hegel model.
   - Relay/host: `crates/vhalla-private-native/src/relay/{mod.rs,tls/**,net.rs,http.rs}`,
     `crates/vhalla-cli/src/{private_host*,private_gateway*,launchd.rs}`,
     `docs/local-host.md`. Re-arm and rotation commands, credential add,
     leaf renewal, host log and probe, gateway lifecycle and supervision,
     `fullfsync` and single post-commit barrier, mutex scope, page-level scan
     barriers, pre-auth deadlines.
   - Agent/MCP: `crates/vhalla-private-native/src/{agent.rs,client/**,grant.rs,relay/delivery.rs}`,
     `crates/vhalla-cli/src/private_rooms/{agent.rs,agent_delivery*,agent_setup.rs}`,
     `docs/cli-agents.md`. Bounds before kernel calls, refusal flushed before
     exit, lazy claim, framing tolerance, persisted watermarks, adaptive poll,
     no idle commits, skip marker, receipt filtering, cheap status reads.
   - Browser: `browser/**`, `crates/vhalla-browser-storage/**`. Actual-bytes
     budget, durable refused entries with in-place reopen, `StopReason`,
     clock clamp, retained bootstrap items, parameterised harness ports.
   - Performance: `crates/vhalla-room-activity-store/**`, `crates/vhalla-journal/**`,
     `crates/vhalla-public-client/**`, `docs/performance.md`, and the new
     steel-thread benchmark example under `crates/vhalla-private-native/examples/`.
     Intent elision, journal barrier reduction, barrier counters, Darwin
     semantics documented, before/after ledger.
   - Journey: `crates/vhalla-cli/tests/private_steel_thread.rs` (new),
     `agent-launch` and `delivery-status` commands in new source files with
     one dispatch edit each, `docs/agent-readiness-plan.md`,
     `docs/release-readiness.md`, replacement of the one-off scripts.
   A finding whose repair crosses a boundary (C1/F1, A5/E-9, E-7, D8) is split
   at the crate boundary; the kernel lane lands typed errors first so the
   driver lanes can match on them.
3. **Integration and final gates.** The integration owner merges the lanes,
   reconciles cross-crate callers, runs the gates in the validation record and
   updates this document's status column.
4. **Acceptance artifacts.** Two are required before any PR is opened: the
   two-agent steel-thread journey test (lane F, Part 3: product host on an
   ephemeral port, two CLI-admitted devices with distinct credentials, two
   `agent-serve --delivery` processes, bidirectional queue, inbox, acceptance,
   host restart and relaunch, foreign-item negative leg, Hegel variant) and
   the steel-thread benchmark (lane E, Section 6: per-stage p50/p95/p99,
   sustained messages per second at 1k and the mailbox cap, barrier counts,
   idle-phase barrier count, RSS and disk growth) with a recorded baseline
   before the repairs and a run after.
5. **PR(s) and release.** One PR per lane or one integration PR at the
   integration owner's choice, exact-head CI aggregate, then a release
   following `docs/release-readiness.md`. The installed v0.2.1 host is not
   touched until the release is admitted.

## Remaining work and promotion criteria

| Area | Useful next bounded result | Evidence required before promotion |
| --- | --- | --- |
| Public relay beyond local | Server-authenticated transport and bounded scheduling on an independently owned host, beyond the loopback and Tailcat setup | Wrong server/token/namespace refusal, slow clients, congestion, restart, exact retry; deployed DNS/TLS evidence; pre-auth starvation bound (A9) |
| Agent OS compartment | One room for a process lifetime; broker retains keys and explicitly mediates provider calls | Actual OS escape probes, denied ambient file/network/process access, grant revocation across waits; unsupported platforms refuse |
| Dead-device recovery | Fresh-device policy model separate from history archives | Partitions, competing recovery, old-device return and interrupted retirement; no reused ratchets/counters or invented legacy authority |
| Independent-machine acceptance | Exact release artifacts exercised on an explicitly owned second machine | Failure-domain identity, bootstrap pin, clean-device journeys, storage-full/crash/partition evidence, measured resource limits, retained failure logs |
| Capacity rotation | `private-host rotate` (or equivalent) that seals the old mailbox and opens a successor namespace under the same CA and tokens; delivery profiles follow it | Hegel test at tiny quotas naming the exhausted quota; rotation keeps old queue read-only as evidence and a retry across rotation returns `duplicate: true`; no re-receipt of old positions |
| TLS renewal | `private-host renew` re-issuing the leaf from the retained CA key; `status` reports days to expiry | Existing delivery bindings open unchanged after renewal; expired-leaf start logs a reason instead of a silent loop; installed host (expires 2027-09-22) renewed in a receipted run |
| Gateway supervision | `private-gateway install/status/uninstall` with a stop flag and drain, sharing `launchd.rs` | SIGTERM completes an in-flight upstream PUT and exits 0; one handler panic does not stop the gateway; 503 with `Retry-After` at capacity |
| Reboot, sleep/wake, logout | Runbook and receipts for login ordering of host, gateway and Tailcat; probe-based readiness | `status --probe` TLS and HTTP empty pages after reboot, 10 min sleep and logout/login; bounded clock regression tolerated by delivery store, RPC session, kernel and browser |
| Long-grant ergonomics | `agent-launch` from a reviewed policy with a session directory; lazy claim; no per-launch fixed counters; graceful expiry reply | 24 h synthetic grant with injected clock keeps polling and answering; second Codex window does not burn the grant; expiry produces a JSON-RPC error before exit; receipts absent from `private_inbox` |
| Delivery status | Durable kernel acceptance index and restart-safe `private_outbox_status`; browser verifies receipts | Hegel model over send, deliver, receipt, restart; forged receipt and receipt for another message never appear; browser and native agree on the same receipt bytes |

Existing anchors still provide no unilateral dead-owner recovery authority;
the previous review's guidance against an archive-to-live shortcut stands.

## Validation record

Run on the integrated tree `claude/steel-thread-20260922` (head at gate time
`09c4848`, merges through `9b4ebc1`); Rust 1.98.1, isolated target dir
`.verify-build` because lane worktrees previously poisoned the shared dir's
same-fingerprint rlib slots.

| Gate | Status |
| --- | --- |
| `cargo +1.98.1 fmt --all -- --check` and `git diff --check` | pass |
| `cargo +1.98.1 clippy --workspace --all-targets --all-features --locked -- -D warnings` | pass |
| CI package matrix lanes for touched crates: `vhalla-private-kernel`, `vhalla-private-protocol`, `vhalla-private-native`, `vhalla-cli` (`experimental-private`), `vhalla-browser-storage`, `vhalla-room-activity-store`, `vhalla-journal`, `vhalla-public-client` | pass (kernel 84, protocol suites, native 119+3+5+1+6, cli private incl. steel-thread, browser-storage 90, activity-store 42 incl. 64-case Hegel, journal 43, public-client 19; `private_agent_delivery` reconciled to outage accounting in 09c4848) |
| Workspace doctests `cargo +1.98.1 test --workspace --doc --all-features --locked` | pass |
| wasm clippy for `browser/` and `vhalla-browser-storage` (`wasm32-unknown-unknown`, `-D warnings`) | pass |
| Browser harnesses: `qualify_private_delivery.mjs` on non-default ports, `qualify_private_panel.mjs`, `qualify_private_session.mjs` with the truncated-archive case | pass: delivery on `--gateway-port 28791 --tls-port 29474` (12 facts, production dist), panel `--production` (12 facts), panel local-qualification on 8789 (13 facts), session on 8789 (archive export/resume/foreign-open facts) |
| Two-agent steel-thread journey test (`tests/private_steel_thread.rs`, single and Hegel) | pass: linear journey 1/1, Hegel interleaved restart/relaunch 4 cases |
| Steel-thread benchmark: baseline at `0eee3b6` and after-repair run, with barrier counts per stage and idle-phase count | pass: lane baseline/after documented in docs/performance.md (218.0s→215.8s ack wall at 100 msg, ledger 5→3 kernel publish barriers); integrated-tree 100-msg run 212.4s ack wall, A 137 ticks/B 133 ticks, 60s idle phase, `/private/tmp/valhalla-perf-integrated-100` |
| Exact-head CI aggregate on the PR head | pass: run 35836605734 at head `bc8f87e`, all 60 checks successful (includes Linux clippy fix `801472e` and archive accounting update `bc8f87e`; archive IndexedDB qualification re-verified locally in real Chromium, window + dedicated worker, with export/import) |

Use Rust 1.98.1 explicitly on this host and the shared target directory
`/private/tmp/valhalla-target-shared`; do not create new target directories.
The installed `me.vhalla.*` services are inspected read-only until release.
