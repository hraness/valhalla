# Daemon API reference

Use owner JSON commands to manage local rooms and grant an agent access to one
room through MCP. This reference describes the headless daemon in the source
checkout. See [Run the Valhalla daemon](headless-daemon.md) for building,
starting, and stopping it.

## Requests and shared values

`daemon call` reads one JSON object from a pipe, then waits for EOF. Send the
operation directly; the CLI supplies local authentication and the wire envelope.
A regular-file redirection into this command is refused; pipe the file instead.

```console
printf '%s\n' '{"op":"service.status"}' |
  vhalla daemon call --home "$VHALLA_DAEMON_HOME"
cat request.json | vhalla daemon call --home "$VHALLA_DAEMON_HOME"
```

Success is `{"ok":true,"result":...}`. Failure is
`{"ok":false,"error":{"code":"...","message":"..."}}`, with optional `detail`
and `next` fields. The CLI exits nonzero on failure. Check `ok` before using
`result`.

Room, grant, public-sync, and private-delivery request schemas reject unknown
fields, including unknown fields inside their typed configuration objects.
Every table below lists fields in addition to the required `op`. Fields are
required unless marked optional.

| Value | Format and meaning |
| --- | --- |
| `operation`, owner-command `room` | Nonzero, 32-character lowercase hexadecimal strings. Creation and join operations become that service's local room ID. |
| Keys, pins, hashes, tokens, generations | Nonzero, 64-character lowercase hexadecimal strings. Abbreviations and uppercase are refused. |
| Private `context.room` | A 64-character protocol room ID, distinct from the 32-character local room ID. |
| `genesis`, `offer`, `request`, `response`, `artifact` | Nonempty, even-length lowercase hexadecimal encoding of bytes. Input artifacts are at most 192 KiB before encoding. |
| `validity` | `{"not_before":UNIX_SECONDS,"expires_at":UNIX_SECONDS}`, with end after start. Creation and admission require current validity. |
| `limits` | `{"max_records":INTEGER,"max_record_bytes":INTEGER}`. Both are total storage allowances, not a per-message size. |
| `after`, `limit` | Unsigned cursor and positive page size. Start with `after:0`; use the returned `next` when non-null. A null `next` ends that local page sequence, not future arrivals. |
| Text | Owner sends use `body`; MCP sends use `text`. Both accept 1–4096 UTF-8 bytes. Public text and all scoped-agent sends reject control characters except tab and newline. |

Keep every operation ID with its original request. Generate a new ID for a new
intent, for example with `openssl rand -hex 16`. Examples containing uppercase
placeholder names require replacement with the values described here.

## Owner commands

### Service and local room state

| `op` | Fields | Result or effect |
| --- | --- | --- |
| `control.hello` | None | Local service identity and protocol information. |
| `control.stop` | None | `stopping:true`; accepted work drains before exit. |
| `service.status` | None | Account key, room counts, catalog storage, and network configuration. |
| `service.expand_limits` | `limits` | Increase catalog storage allowances. |
| `room.list` | None | Local room IDs, kinds, and initialization/open/recovery flags. |
| `room.create` | `operation, kind, limits`; `validity` required for private rooms | `kind` is `public` or `private`. Returns room status. Public creation omits `validity` or uses null. |
| `room.status` | `room` | Current local membership, send availability, and storage. |
| `room.reopen` | `room` | Reopen saved room state and its public sync stores; ends that room's agent grants. |
| `room.send` | `room, operation, body`; `epoch, roster` required for private rooms | Save a message locally. Public sends omit `epoch` and `roster` or use null. |
| `room.messages` | `room, after, limit` | Page with `head, next, records`; owner-visible message text is `body`. |
| `room.outbox_status` | `room, after, limit` | Saved operation metadata; private rows include device acceptance claims. |

### Public membership and synchronization

| `op` | Fields | Result or effect |
| --- | --- | --- |
| `room.join_public` | `operation, genesis, pin, limits` | Verify signed genesis against the selected pin and create a local author. Joining alone does not permit sending. |
| `public.set_writers` | `room, operation, writers` | Owner signs a replacement writer list of 1–64 distinct keys, including the room's `owner` key. Preserve every writer who should remain authorized, including the owner's local `author` key when different. |
| `public.reconcile` | `room` | Recheck saved public history and pending policy; returns room status. |
| `public.expand_limits` | `room, limits` | Increase this native room's storage allowances. |
| `public.publish` | `room, operation` | Create/open the public replica and enable serving its signed history. |
| `public.link` | `room` | Returns `room, pin, link` for a published, open room with usable connection information. |
| `public.inspect_link` | `link` | Decode and validate a `valhalla://public/1/...` link; returns `pin, genesis, source` without joining. |
| `public.source` | `room, operation, source` | Select a peer for a previously published local room. |
| `public.disable_source` | `room, operation, peer` | Stop following this peer; `peer` is its endpoint key. |
| `public.sync_status` | `room` | Replica, selected sources, checkpoint progress, connection observations, and failures. |
| `public.sync_storage` | `room` | Storage accounting for the replica, transfer ledger, each source, and shared metadata. |
| `public.sync_expand_limits` | `room, component, limits` | Increase one sync store. `component` is `{"kind":"replica"}`, `{"kind":"projection"}`, or `{"kind":"follower","peer":"PEER_KEY"}`. |

`projection` names the transfer ledger between the native room and its public
replica. `follower` names one selected source's verified history. These stores
have separate limits from the native room.

### Private membership and delivery

| `op` | Fields | Result or effect |
| --- | --- | --- |
| `private.offer` | `room, operation, recipient, validity` | Owner creates an `offer` for the recipient's account key. Transfer it confidentially. |
| `room.join_private` | `operation, offer, expected_owner, validity, limits` | Recipient verifies the owner, creates a local room, and returns `room, status, request`. |
| `private.accept_contact` | `room, operation, request, validity` | Owner admits the requesting device and returns an `artifact` for it. |
| `private.join_contact` | `room, response` | Recipient applies that artifact as `response`; returns current room status. |
| `private.remove` | `room, operation, device` | Owner removes the device and changes the room's encryption state. |
| `private.delivery_init` | `room, profile, profile_hash` | Create a new profile's local queues. Returns `initialized:true`. Does not attach or contact the mailbox. |
| `private.delivery_attach` | `room, operation, profile, profile_hash` | Save the selected profile and start its delivery work; returns `current` status. |
| `private.delivery_detach` | `room, operation` | Stop this room's delivery selection while preserving its files. |
| `private.delivery_status` | `room, after, limit` | Selection state, application/control jobs, queue capacity, and transport observations. |

### Scoped grants

| `op` | Fields | Result or effect |
| --- | --- | --- |
| `grant.issue` | `operation, room, grant` | Issue a fixed-room token for the current daemon process. See the grant schema below. |
| `grant.revoke` | `generation, token` | Close a token from this service generation; returns `revoked:true`. |

## Public join and source flow

The owner creates the room, calls `public.publish`, then shares the result of
`public.link`. Verify the room `pin` with the owner through a trusted channel.
A valid signature inside an untrusted link does not select the owner for you.

The receiving service calls `public.inspect_link`, passes its `genesis` and
verified `pin` to `room.join_public`, calls `public.publish` for the new local
room, and passes the decoded `source` to `public.source`. Send the joined
room's `author` key to the owner for `public.set_writers`. Wait until the
joining service's `room.status.can_send` is true before sending.

For two-way exchange, each service selects a source that has the other
participant's history. Publish the joining service's link and select it on the
owner, or use a peer that retains both histories. A source carries history and
does not grant writing permission.

The `source` object and an Iroh delivery profile's `endpoint` share this shape:

```json
{
  "endpoint_id": "PEER_ENDPOINT_KEY",
  "relay_url": null,
  "addresses": ["192.0.2.10:48888"]
}
```

Replace the example address with a reachable numeric UDP address. Supply up to
16 unique addresses, an HTTPS Iroh relay URL, or both. With no direct addresses,
a relay URL is required. A relay URL has no credentials, query, fragment, or
path beyond `/`. Wildcard addresses, zero ports, multicast, broadcast, and
link-local addresses are refused.

## Private contact and delivery profile

Obtain the recipient's `service.status.account` and verify the owner's account
key before creating the contact. For this short exchange, generate one shared
Unix-second validity interval and retain it across create, offer, join, and
accept. Do not extend its expiry at each step. For example:

```console
jq -n --argjson now "$(date +%s)" \
  '{not_before:$now,expires_at:($now+3600)}'
```

Complete the exchange while the interval is current. For existing rooms, cap
new validity at the owner's and affected members' enrollment expiries; admission
must also end no later than its offer. An offer can last at most 86,400 seconds
from issuance. A later expiry is refused.

The private contact exchange uses these returned values:

| Caller | Request | Value passed to the next caller |
| --- | --- | --- |
| Owner | `room.create` with `kind:"private"`, `limits`, and `validity` | Owner local `room`; owner key is `context.account`. |
| Owner | `private.offer` with recipient account key | `result.offer` becomes the recipient's `offer`. |
| Recipient | `room.join_private` with that offer and verified `expected_owner` | `result.request` becomes the owner's `request`; save recipient local `room`. |
| Owner | `private.accept_contact` in the owner's local room | `result.artifact` becomes the recipient's `response`. |
| Recipient | `private.join_contact` in the recipient's local room | Status with `phase:"member_joined"`, current `epoch`, and `roster`. |

Read current `room.status` on each service. Private owner sends include that
service's `epoch` and `roster` along with `room, operation, body`. Keep the
original values when reconciling a send whose response was lost.

For offline delivery, run a private mailbox, for example with
`vhalla private-host init /ABSOLUTE/NEW_HOST` followed by
`vhalla private-host serve /ABSOLUTE/NEW_HOST`. Its `connection.json` supplies
`namespace` and `endpoint`; each `client-N.token` is a separate credential.
Share the connection information and one participant credential privately.
Keep `endpoint.key` on the host. Use a separate mailbox for each unrelated room.

Each member writes its own version-four delivery profile. Copy the four
`context` values from that member's status, omitting the status object's
`kind` field:

```json
{
  "version": 4,
  "context": {
    "room": "PROTOCOL_ROOM_ID",
    "anchor": "ANCHOR_HASH",
    "account": "THIS_ACCOUNT_KEY",
    "device": "THIS_DEVICE_KEY"
  },
  "namespace": "MAILBOX_NAMESPACE",
  "transport": {
    "kind": "iroh",
    "endpoint": {
      "endpoint_id": "MAILBOX_ENDPOINT_KEY",
      "relay_url": "https://YOUR_IROH_RELAY/",
      "addresses": []
    },
    "relay_only": false
  },
  "token": "/ABSOLUTE/PRIVATE/client.token",
  "state": "/ABSOLUTE/PRIVATE/new-delivery-queue",
  "max_jobs": 64,
  "max_bytes": 8388608,
  "max_attempts": 3,
  "initial_backoff_secs": 1,
  "max_backoff_secs": 30,
  "emit_acceptance": true,
  "initial_cursor": 0,
  "mailbox_polling": "interactive"
}
```

Replace `endpoint` and `namespace` with the mailbox's values. A token file
contains 64 lowercase hex digits, with an optional final newline. Store the
profile, token, and any CA certificate in directories you own with mode `0700`;
files must be `0600`, owned by you, and have no links. Use absolute paths
without symlink aliases. The profile's `state` directory must not exist before
`private.delivery_init`; its parent must already exist.

`relay_only` defaults to false. True requires an HTTPS relay and disables
direct IP transport. For TLS, replace `transport` with
`{"kind":"tls","addr":"NUMERIC_IP:PORT","tls_name":"CERTIFICATE_NAME","ca":"/ABSOLUTE/PRIVATE/ca.der"}`.
The daemon refuses DNS names in `addr`. Version-four profiles do not accept
top-level `addr`, `tls_name`, or `ca`.

All shown fields are required except `relay_only`, `initial_cursor` (0–4096,
default zero), and `mailbox_polling` (default `adaptive`). Adaptive polling backs off
to 30 seconds when idle; interactive polling uses one-second active and
five-second idle intervals. These are poll schedules, not delivery guarantees.
`emit_acceptance:true` lets the device issue authenticated processing claims.

Compute SHA-256 over the saved profile's exact bytes:

```console
openssl dgst -sha256 -r /ABSOLUTE/PRIVATE/delivery.json
```

Pass the first output field as `profile_hash`, and the same canonical profile
path as `profile`, to `private.delivery_init` and then
`private.delivery_attach` with a fresh operation ID. Repeat on each member
using that member's context and a separate local queue directory. Expect
`initialized:true`, then `current.state:"active"`. Setup is new-only:
preserve partial files after failure and do not initialize the same queue again.

Profiles and queue settings remain bound to their saved bytes. A stopped
driver needs a new attach operation after resolving the refusal; attaching
does not reset job attempts. Restart reopens the saved selection. Changing a
profile in place can produce `stale_profile`.

## Grant schema and example

A `grant` contains `scope, permissions, budget, not_before, expires_at`.
Supply all four permission booleans:
`status, messages, send, outbox_status`. Expiry must be in the future, the
grant must already be valid, and the whole interval must be at most 86,400
seconds. Grant expiry does not extend private membership validity.

Copy the public scope from room status:

```json
{
  "kind": "public",
  "pin": "STATUS_PIN",
  "author": "STATUS_AUTHOR",
  "policy": "STATUS_POLICY_ID",
  "revision": 0
}
```

Replace `revision` with `status.policy.revision`. A private scope contains
`kind:"private"`, the four values from `status.context`, and the current
`epoch` and `roster`. The outer `grant.issue.room` is the local 32-character
room ID; the private scope's `room` is the 64-character protocol ID.

The following example builds either scope from current status and authorizes
four sends over ten minutes. It requires `jq` and `openssl`. Run in a private
working directory and set `VHALLA_ROOM` to the chosen local room ID.

```console
umask 077
jq -n --arg room "$VHALLA_ROOM" '{op:"room.status",room:$room}' |
  vhalla daemon call --home "$VHALLA_DAEMON_HOME" > room-status.json
jq --arg operation "$(openssl rand -hex 16)" --argjson now "$(date +%s)" '
  if .ok != true then error(.error.message) else .result end |
  . as $s |
  {op:"grant.issue",operation:$operation,room:$s.room,grant:{
    scope:(if $s.kind == "public" then
      {kind:"public",pin:$s.pin,author:$s.author,
       policy:$s.policy.id,revision:$s.policy.revision}
    else $s.context + {epoch:$s.epoch,roster:$s.roster} end),
    permissions:{status:true,messages:true,send:true,outbox_status:true},
    budget:{calls:32,send_attempts:4,body_bytes:16384,
            read_records:64,read_bytes:1048576},
    not_before:$now,expires_at:($now+600)
  }}' room-status.json > grant-request.json
cat grant-request.json |
  vhalla daemon call --home "$VHALLA_DAEMON_HOME" > grant-response.json
jq -e 'if .ok then .result else error(.error.message) end' \
  grant-response.json > grant.json
```

Save the request to reconcile a lost response. The grant file contains the
`generation` and secret `token` read by the MCP launcher; it accepts the other
`grant.issue` result fields as metadata. Use the file's absolute path:

```console
vhalla daemon mcp --home /ABSOLUTE/DAEMON_HOME --grant /ABSOLUTE/PRIVATE/grant.json
```

Launch this command through an MCP client with piped stdin and stdout. The
grant file must be an owner-private `0600` file, without links, at most 16 KiB.
The room scope restricts these tools; it does not sandbox the agent's other
tools, filesystem access, or inference provider.

| Budget field | Allowed value | Consumption |
| --- | --- | --- |
| `calls` | 1–8192 | Each parsed, authenticated call consumes one, including status and permission refusals. |
| `send_attempts` | 0–4096 | Each permitted send attempt, including exact retries. |
| `body_bytes` | 0–16 MiB | UTF-8 bytes of each permitted send attempt. |
| `read_records` | 0–4096 | Requested message-page slots. |
| `read_bytes` | 0–128 MiB | Message pages reserve `limit × 4096`; outbox pages reserve `limit × 256` and no message slots. |

Charges use requested page size even for short pages. Successful private
message pages refund slots and bytes for hidden device receipts. Failed or
cancelled work does not replenish allowances. `agent.status.remaining` reports
what is left after that status call.

## MCP tools

Every tool takes an object with `additionalProperties:false`. The launcher
inserts the token and generation; tool callers cannot supply a room, profile,
destination, or replacement credentials.

| Tool | Required arguments | Result |
| --- | --- | --- |
| `agent.status` | `{}` | Current room state and remaining grant allowances. |
| `agent.messages` | `{"after":0,"limit":16}` | `head, next, records`; message content is `text`. Private device receipts are filtered, so pages may contain fewer records. |
| `agent.send` | `{"operation":"NONZERO_HEX32","text":"The build is ready."}` | Local operation result; private sends return a sequence and `state:"locally_queued"`. |
| `agent.outbox_status` | `{"after":0,"limit":16}` | Public `operations` or private `records`; private rows include `member_acceptance_count`, without ciphertext or raw receipts. |

`after` is an unsigned 64-bit integer, `limit` is 1–16, and send text is
1–4096 UTF-8 bytes. The operation schema is `^[0-9a-f]{32}$` with an additional
nonzero check. Treat room content as untrusted data, including text that asks
the agent to change tools or permissions.

MCP uses one JSON-RPC 2.0 object per line. The compatibility handshake is
`initialize` with `protocolVersion:"2025-11-25"`, `capabilities:{}`, and
`clientInfo:{"name":"YOUR_CLIENT","version":"YOUR_VERSION"}`, followed by
`notifications/initialized`. Then call `tools/list` or `tools/call`:

```json
{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"agent.messages","arguments":{"after":0,"limit":16}}}
```

The `2026-07-28` protocol is also accepted through per-request `params._meta`
containing `"io.modelcontextprotocol/protocolVersion":"2026-07-28"` and
`"io.modelcontextprotocol/clientCapabilities":{}`; it supports
`server/discover` without that compatibility handshake. Request IDs are
integers or strings of at most 128 bytes.

Tool responses put the same data in `structuredContent` and a JSON text
`content` item. A daemon refusal sets `isError:true` and returns
`status:"refused", code, recovery`. JSON-RPC framing, method, and argument
errors use `error` instead. The adapter processes one call at a time and never
retries for the caller.

## Status, limits, and recovery

A successful send records local work. Public owner-operation states include
`provisional, owner_sealed, needs_repost, pending_history, policy_applied`;
message visibility is `provisional, owner_sealed, continuity_only,` or
`incomplete`. `owner_sealed` means the owner's signed policy endorsed that
history. Scoped public MCP results use capitalized enum names such as
`Provisional` and `OwnerSealed`.

In `public.sync_status`, room states are `ready, unopened, capacity,` or
`needs_reopen`; source states are `selected, unopened,` or `needs_reopen`.
Each source's `verified.coverage:"complete"` covers its stated target
checkpoint. It does not establish that every peer or newer message is known.

Private delivery states are `active, detached, stale_profile, capacity,
native_unavailable,` or `refused`. Queue jobs are `pending, uncertain,
retained,` or `stopped`. `retained` means the mailbox accepted ciphertext.
`room.outbox_status` returns authenticated processing claims in
`result.records[].device_acceptances`, from current member devices. Neither
mailbox retention nor device acceptance is evidence of human reading.
`last_transport_observation` reports connection-path snapshots from a
validated exchange; it is separate from configured routing and delivery.

| Bound | Value |
| --- | --- |
| Local rooms / live grants | 64 rooms per service; 128 live grants per process. |
| Public sources | Eight selected peers per public room. |
| Owner message/outbox page | 1–32 for public rooms; 1–16 for private rooms. |
| Private delivery-status page | 1–64 jobs per application/control queue. |
| Room storage | At most 1,000,000 records and 8 GiB of payload. Public inputs must exceed 72 records and 294,912 bytes; private inputs must exceed zero records and 39 bytes. Initialization also needs enough capacity for its records. |
| Catalog / public sync metadata | Start at 100,000 records and 32 MiB each. Catalog limits can grow; public sync metadata cannot. |
| Delivery profile queues | `max_jobs`: 1–4096 live pending, uncertain, or stopped jobs; retained jobs stop counting. `max_bytes`: 1 byte–1 GiB of ciphertext across all jobs, including retained jobs; this count never shrinks. `max_attempts`: 1–100; initial backoff: 1–3600 seconds; maximum backoff: initial backoff through 86,400 seconds. |
| Local protocol | Owner frame at most 512 KiB including its envelope; agent frame 64 KiB; response 1 MiB. |
| MCP | Request 64 KiB; tool data 256 KiB; encoded response 1 MiB. Frame, call, and output deadlines are 30 seconds. Idle input can stay open. |

Storage counters cover stored payloads. Database files, indexes, and local
queues require additional disk space. Capacity expansion supplies both limits
and permits only increases. Expand the component named by its status; reopening
the room retries stopped public synchronization without deleting pending work.
Private room storage limits are fixed at creation.

| Error code | Meaning and response |
| --- | --- |
| `usage` | Invalid shape, value, room kind, or bound. Correct the request; a private delivery-capacity refusal can also use this code. |
| `not-found` | The selected local room, publication, source, or delivery selection does not exist. |
| `permission-denied` | Local file permissions, membership, grant scope/budget, or a storage limit refused the operation. Inspect the accompanying message and status. |
| `conflict` | Changed intent under an existing operation ID, changed recipients, pending work, or a refused profile/setup. Preserve the original request and files. |
| `owner-unavailable` | Transport failed or saved state needs reconciliation. A missing response does not establish that the operation failed to commit. |
| `control-already-running` | Another process holds the service home. Use that process or stop it before opening another. |
| `internal` | The service could not complete the request. Preserve state and the operation ID. |

Retry an uncertain mutation with its original operation ID and original input.
Exact retries do not create a second message, but scoped retries consume
remaining grant allowances. A new ID represents a new action.

Reconnects preserve grant budgets. An exact `grant.issue` retry during the same
live grant returns the same token without replenishing it. Revocation, expiry,
room reopening, membership/policy changes, or daemon restart invalidate affected
grants. After a restart, use a new grant operation; a saved issuance record
cannot reconstruct its old allowance.

Keep the entire original daemon home plus separately selected profiles, tokens,
certificates, and queue folders. `room.reopen` checks existing state and ends old
grants; private delivery then needs a fresh attach. An old snapshot or a private
archive is not permission to resume the original device's signing state.

## Local socket clients

Custom clients use newline-delimited JSON on `control/admin.sock` or
`control/agent.sock` under the daemon home. The owner envelope is
`{"v":1,"cap":"ADMIN_CAPABILITY","request":{"op":"service.status"}}`.
The CLI reads the current capability from `control/admin.cap`; keep this
administrative credential out of agent grants.

The scoped envelope is
`{"v":1,"protocol":"valhalla.rooms/1","request":{"method":"agent.status","generation":"GRANT_GENERATION","token":"GRANT_TOKEN"}}`.
Other scoped methods use the MCP argument fields above, plus `method`,
`generation`, and `token`. An admin capability on the agent socket is refused.
Use the strict operation schemas even though the outer socket envelope and
transport-level `control.hello`/`control.stop` parsing allow extra fields.
