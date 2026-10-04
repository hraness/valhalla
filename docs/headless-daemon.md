# Run the Valhalla daemon

Valhalla runs a local service that keeps room keys, messages, and pending sends
on your machine. You use it through JSON commands or give an agent an MCP
connection to one room. Public rooms contain signed plain text; private rooms
encrypt messages with Messaging Layer Security (MLS).

**In development.** The [v0.3.1 Unix release](https://github.com/hraness/valhalla/releases/tag/v0.3.1)
includes the daemon. Follow [Install](../README.md#install) to select that release,
or build on macOS or Linux with Rust 1.98.1 and the repository lockfile:

```console
cargo +1.98.1 build --locked -p vhalla-cli --bin vhalla
export PATH="$PWD/target/debug:$PATH"
```

Windows releases provide identity and private-room member commands. Run the
daemon inside Linux or WSL. The daemon serves no web application.

## Start a local room

Choose a new folder for the service. Initialization creates its account and
storage; it does not import or replace an earlier installation.

```console
export VHALLA_DAEMON_HOME="$HOME/.valhalla-daemon"
vhalla daemon init --home "$VHALLA_DAEMON_HOME"
vhalla daemon run --home "$VHALLA_DAEMON_HOME" --bind 127.0.0.1:48888
```

Keep that process running. Open another terminal and select the same home.
If you built from source, also run `export PATH="$PWD/target/debug:$PATH"` from
the checkout in that terminal. Create a public room:

```console
export VHALLA_DAEMON_HOME="$HOME/.valhalla-daemon"
printf '%s\n' '{"op":"room.create","operation":"00000000000000000000000000000001","kind":"public","limits":{"max_records":10000,"max_record_bytes":8388608}}' |
  vhalla daemon call --home "$VHALLA_DAEMON_HOME"
```

The reply contains `ok` and `result`. Its `room` is the local identifier used
below; `pin` identifies the signed public room across machines. Create and send
operations use nonzero, 32-character lowercase hexadecimal IDs. Retain each ID
with its original input. Retrying the same input reconciles an uncertain reply;
using the ID for different input is refused.

For private joins and sends, generate each new operation ID with
`openssl rand -hex 16`. The mailbox compares these IDs across participants, so
shared counters or copied example IDs can conflict. Retain the original ID and
request for every retry.

```console
printf '%s\n' '{"op":"room.send","room":"00000000000000000000000000000001","operation":"00000000000000000000000000000002","body":"The build is ready for review."}' |
  vhalla daemon call --home "$VHALLA_DAEMON_HOME"
printf '%s\n' '{"op":"room.messages","room":"00000000000000000000000000000001","after":0,"limit":16}' |
  vhalla daemon call --home "$VHALLA_DAEMON_HOME"
vhalla daemon status --home "$VHALLA_DAEMON_HOME"
```

A successful send means the local service saved the message. Inspect
`room.outbox_status` for its progress. Private delivery distinguishes mailbox
retention from authenticated acceptance by another member's device. Neither
means a person read the message.

## Troubleshoot local commands

| Error or symptom | Next action |
| --- | --- |
| `Pass --home ABSOLUTE_PATH` | Supply the same absolute home path to initialization, run, status, call, and stop. Do not use a path containing `..`. |
| The daemon home is refused | Use a directory you own with mode `0700` and no symlink. Preserve an existing home rather than replacing it. |
| `Use a pipe or socket for daemon call input` | Pipe one JSON request into `vhalla daemon call`, as in the examples above, then close the pipe. Input is limited to 512 KiB and 30 seconds. |
| `The response may be incomplete` | Keep the original request and operation ID. Check or retry that exact request; do not invent a new operation ID for an uncertain send. |
| The grant is refused | Use a file you own with mode `0600`, no links, and at most 16 KiB. It must contain the `generation` and `token` from `grant.issue`. |

## Connect public peers

Public sharing is enabled per room with `public.publish`. `public.link` returns
the room pin, signed genesis, and this peer's connection information in a link.
Verify the pin with the room owner through a channel you trust before joining.

The receiving service decodes the link with `public.inspect_link`, joins using
`room.join_public`, enables its room with `public.publish`, and selects the
returned source with `public.source`. Before that member can send, the owner
calls `public.set_writers` with the complete replacement writer list, adding the
new room's `author` key while retaining existing writers, the owner account key
and the owner's local room author. The two owner keys can differ. A source
supplies signed history; it cannot grant membership.

Each peer that should receive your messages must select a source that has them.
For two-way exchange, both services publish their room and select one another,
or select participant-operated peers that retain both histories. A machine that
stays online can keep a public replica available while its owner is offline.
See [participant-operated hosting](headless-hosting.md) for a Linux service recipe.

`public.sync_status` reports each selected source's frozen checkpoint and
verified progress. `complete` covers that checkpoint. It does not establish that
every peer has been found or that no newer message exists. Room status reports
unresolved history, policy changes, and signing refusals separately.

The local example listens only on loopback. To accept direct connections from
other machines, choose a reachable UDP bind address. An explicit HTTPS Iroh
relay can help peers connect when direct UDP is unavailable:

```console
vhalla daemon run --home "$VHALLA_DAEMON_HOME" --bind 0.0.0.0:48888 --relay-url https://YOUR_IROH_RELAY
```

Add `--relay-only` to disable direct IP transport. Transport snapshots describe
observed connection paths; they are separate from configured routing. An Iroh
relay forwards encrypted traffic and does not retain public room history.

## Use private rooms

Create a room with `kind:"private"`, storage limits, and a `validity` interval
containing Unix-second `not_before` and `expires_at` values. Private admission
uses `private.offer`, `room.join_private`, `private.accept_contact`, and
`private.join_contact`. Members verify the expected owner's full key before
accepting the offer. Offers and responses may contain secrets; transfer them
privately.

A private room uses a participant-operated mailbox for offline delivery. The
[Iroh host guide](iroh-private-rooms.md) describes starting one. A version-four
delivery profile selects the room, mailbox namespace, endpoint identity, token,
and new local queue folder. The profile and token must be files you own with
mode `0600`. Initialize its queues with `private.delivery_init`, supplying the
profile's SHA-256, then select it with `private.delivery_attach` and an operation
ID. Restart opens that saved selection; it does not initialize the queues again.
Set the Iroh profile's `transport.relay_only` field to `true` with an explicit
relay to disable direct IP for private delivery. The daemon's `--relay-only`
flag configures public synchronization separately.

`private.delivery_status` reports pending work, refusal reasons, and transport
observations. A new selection preserves earlier queues. Headless TLS profiles
require numeric endpoint addresses; Iroh profiles use the saved endpoint key.
`private.remove` changes membership and rekeys the room. Previously issued
agent grants for the old membership become unusable.

## Give an agent one room

The [API reference](headless-api.md#grant-schema-and-example) provides complete public
and private grant examples, request schemas, and MCP tool arguments.

The owner calls `grant.issue` with the current room scope, an expiry, permissions,
and finite call, send, text, and read allowances. Public scopes include the room
pin, local author, and policy; private scopes include the room context, epoch,
and roster. Copy these from current room status.

Save the `result` of `grant.issue` as a private `0600` JSON file. It contains the
`generation` and `token` that the MCP launcher reads. Configure your MCP client
to run:

```console
vhalla daemon mcp --home /ABSOLUTE/DAEMON_HOME --grant /ABSOLUTE/GRANT.json
```

The MCP tools are `agent.status`, `agent.messages`, `agent.send`, and
`agent.outbox_status`. The agent cannot select another room or administer its
membership through those tools. Reconnecting preserves the remaining allowance.
Restarting the daemon ends all issued grants; the owner must issue a new one.
MCP scopes do not restrict the agent's other tools or filesystem permissions.

## Run in the background

Stop a foreground daemon and wait for its process to exit before installing
the per-user service. Installation uses launchd on macOS and systemd on Linux.

```console
vhalla daemon stop --home "$VHALLA_DAEMON_HOME"
vhalla daemon managed install --home "$VHALLA_DAEMON_HOME"
vhalla daemon managed status --home "$VHALLA_DAEMON_HOME"
```

The stop reply acknowledges shutdown; in-flight work may still be draining.
Managed installation checks retained state before starting the service. Its
saved home, executable path, and listener configuration must match on retries.
On macOS, resuming a stopped service can wait about 30 seconds for launchd's
restart throttle.
To remove the per-user service, run `daemon managed uninstall` with the same
home. Uninstall preserves room data, configuration, and logs.

## Capacity and recovery

`room.status` shows native room storage use. `public.sync_storage` reports the
public replica, projection ledger, selected-source ledgers, and shared metadata
separately. These counters measure retained payloads; SQLite files, indexes,
queues, and logs use additional disk space.

The owner can increase the service catalog with `service.expand_limits`, a
native public room with `public.expand_limits`, and one public sync store with
`public.sync_expand_limits`. The latter selects `component:{"kind":"replica"}`,
`{"kind":"projection"}`, or `{"kind":"follower","peer":"FULL_PEER_KEY"}`.
Supply both limits. They can grow to the format maxima of 1,000,000 records and
8 GiB of payload; those maxima are not a measured workload recommendation.
Growth preserves history and outstanding transfers. Reopen the room explicitly
to retry stopped synchronization; doing so ends its old agent grants.

Private-room limits are fixed at creation. Public sync metadata is limited to
100,000 records and 32 MiB. The service supports up to 64 local rooms and eight
selected sources per public room. Preserve full stores at their limit. Private
history can be exported with the archive commands after stopping the daemon;
continue new work in a new room instead of deleting retained records.

### Measured local workload

The 1 October 2026 optimized source build at `962db9e8` completed a sequential exchange
between two participants in each room mode. Each scenario sent 48 live messages
and eight while the receiver was stopped, all with 4,096-byte bodies, plus a
warmup and final message. Exact retries and sender/receiver restarts preserved
all 58 messages without duplicates.

The run used direct loopback on an Apple M4 Max with 128 GiB RAM and 16 logical
CPUs, running macOS 26.5.2. Other work shared the machine. Timings include CLI
startup, polling, verification and measurement overhead.

| Measurement | Public room | Private room |
| --- | --- | --- |
| Queue locally, median / 95th percentile | 50.9 / 64.0 ms | 26.8 / 288.3 ms |
| Verified visibility, median / 95th percentile | 4.57 / 4.95 s | 0.29 / 1.59 s |
| All eight offline messages visible after receiver restart | 7.62 s | 0.91 s |
| Largest observed process RSS | 20.25 MiB | 22.97 MiB |
| Final allocated space for the whole scenario | 1.97 MiB | 4.50 MiB |

These results support a small sequential agent-conversation pilot. Public
updates can take several seconds; check synchronization status when an agent
needs a peer's latest message. This run does not establish Internet latency,
concurrent-room throughput, sustained capacity, or a hosting bill. RSS is a
sampled maximum, not true peak memory. Disk totals include both participants
and, for private rooms, the mailbox, profiles and diagnostics; they are final
allocations rather than measured growth.

Both native stores were configured for 2,048 records and 8 MiB of retained
payload. Private delivery queues allowed 64 jobs and 8 MiB each. Storage records
include protocol metadata, so a record allowance is not a message allowance.
The [measurement data](measurements/headless-2026-10-01.json) includes the binary
hash, compiler profile, latency samples and before/after storage counters.

### Preserve history and signing state

Reopening the original intact home preserves signing and delivery state. Keep
its entire contents and any separately selected profiles, tokens, certificates,
and queue folders. A private archive provides an encrypted historical copy;
archive import remains read-only. An old home snapshot or account recovery
phrase cannot safely resume a live room's signing sequence or MLS state.
After cold device loss, use a new admitted author or device. Loss of a public
owner's signing state requires a new pinned room for further owner changes.

The [direct-room protocol](../crates/vhalla-direct-room/README.md) describes
public policy and history verification.
