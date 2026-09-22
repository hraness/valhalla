# Private rooms for CLI agents

The maintained `vhalla private agent-serve` command is a local MCP server for
existing CLI agents, including Codex and Devin. It binds one existing account,
room, device, epoch and roster for one finite session. Use a build containing
`experimental-private`; the release workflow includes this feature. Source
implementation and local qualification are distinct from a published release
and an independently qualified relay. See [agent readiness](agent-readiness-plan.md)
for the current delivery status.

## What is authorized

Trusted setup selects a read-only or read-write grant, finite message/read
budgets, an expiry, and either a fixed inbox snapshot or a bounded future inbox
range. The server exposes exactly five tools: `private_status`, `private_inbox`,
`private_prepare`, `private_queue`, and `private_outbox_status`. Each call carries
the session identifier advertised in its tool schema. Tool arguments cannot
select another room, path, provider, credential or network endpoint.

This is a cooperating-host interface. Codex or Devin may have other tools and
ambient filesystem/network access, and their configured inference provider
receives the material they read. The host declaration below is not a provider
attestation or an operating-system sandbox. Room text is untrusted content;
it does not authorize granting more tools or changing the disclosure boundary.

## Prepare one launch

First complete explicit confidential admission with the
[private-room commands](private-rooms.md). `private inspect` writes authenticated
membership and current context to an owner-private output. Account-key recovery does not recreate an
erased live device: use the current owner's fresh-device admission or an explicit
new room. Archives remain read-only history.

Keep configuration, secrets and outputs outside source control, in a directory
owned by the operator with mode `0700`; input files must be `0600`. Create a
disclosure JSON containing the actual host and selected provider/model, for
example (replace the descriptive values before use):

```json
{
  "host": "My Mac, existing Codex CLI",
  "provider": "the inference provider selected in this CLI session",
  "model": "the exact selected model",
  "processing_policy": "I authorize this provider to process the selected room messages",
  "allow_cooperating_host": true
}
```

Generate a new grant and select a never-used claim path:

```sh
vhalla private agent-grant /absolute/account /absolute/room \
  --mode read-write --disclosure /private/config/disclosure.json \
  --receipt /private/config/claim-001.json --out /private/config/grant-001.json \
  --lifetime 900 --follow-inbox true --max-read-records 256 \
  --max-messages 32 --max-body-bytes 131072
```

Without `--follow-inbox true`, the default grant reads only the inbox snapshot
present at setup. Following uses an explicit finite ceiling, at most 4,096
positions beyond the initial head; it never renews read credits. Membership or
epoch changes end the grant before further agent output is released.

The grant is durably consumed once before exposing tools, even if the process
later exits cleanly. An automatic reconnect with the same grant refuses. Preserve
the grant claim, room, and queue; reconcile any uncertain operation before
preparing a **new explicit grant with a new claim path**. Never delete a claim,
roll back custody, or copy a live device to renew permission. One room and account
can have one active custodian; use separately admitted devices for simultaneous
Codex and Devin sessions.

## Connect the CLI

Use absolute paths to the admitted executable, identity, room and private grant.
Codex supports a local stdio process configured as an MCP server; its
configuration is shared with other local Codex clients.
([Official Codex MCP documentation](https://developers.openai.com/codex/mcp))

```sh
codex mcp add valhalla -- /absolute/vhalla private agent-serve \
  /absolute/account /absolute/room --grant /private/config/grant-001.json
```

For project-specific Codex setup, use a trusted project's `.codex/config.toml`
with the equivalent command/args, rather than registering the same one-use grant
for unrelated sessions. Use `required = true`, `startup_timeout_sec = 30` and
`tool_timeout_sec = 35` so a failed launch is visible. Keep that local config out
of source control. The stdio server requires pipes and emits only MCP JSON;
running it directly in an interactive terminal is deliberately refused.

Devin's installed CLI supports project-local registration, as verified with
`devin mcp add --help` on 22 September 2026:

```sh
devin mcp add valhalla --scope local -- /absolute/vhalla private agent-serve \
  /absolute/account /absolute/room --grant /private/config/grant-001.json
```

Start only the intended agent after preparing the grant. Codex app-server
0.155.1 was exercised with `thread/start` and `mcpServer/tool/call`. Its separate
`mcpServerStatus/list` inventory probe opens another MCP process; do not use that
probe to restart or diagnose an already consumed one-use grant. Inspect the
active thread's discovered tools and call `private_status` through that thread.
A configuration listing
is not a successful MCP connection. Check that all five tools are present, call
`private_status`, and verify the selected room and grant. The server supports
MCP `2026-07-28` and initialization-based `2025-11-25`; unsupported versions
refuse rather than relaxing scope.

## Local hosting and persistent TLS delivery

Use [local host setup](local-host.md) to initialize the Mac mailbox, keep its
service running and configure a saved Tailcat key when remote access is needed.
Host sleep delays delivery; it does not lose or renew the queued work. No paid
server or public domain is required.

Without `--delivery`, queueing is durable local storage only. A separately
selected host profile can submit exact retained ciphertext and stage incoming
items while the same process owns the room. The profile is never an agent tool
argument. Use a private JSON file with this exact shape:

```json
{
  "version": 1,
  "context": {
    "room": "64 lowercase hex digits from authenticated inspect",
    "anchor": "64 lowercase hex digits from authenticated inspect",
    "account": "64 lowercase hex digits from authenticated inspect",
    "device": "64 lowercase hex digits from authenticated inspect"
  },
  "namespace": "64 lowercase hex digits from the selected host connection.json",
  "addr": "127.0.0.1:7443",
  "tls_name": "relay.example.invalid",
  "ca": "/private/config/relay-ca.der",
  "token": "/private/config/relay-token.hex",
  "state": "/private/config/new-delivery-state",
  "max_jobs": 1024,
  "max_bytes": 67108864,
  "max_attempts": 20,
  "initial_backoff_secs": 5,
  "max_backoff_secs": 300,
  "emit_acceptance": true,
  "initial_cursor": 0
}
```

Replace the illustrative address and fields with the explicitly selected relay.
The token file contains 64 lowercase hex digits, optionally followed by one
newline. TLS validates the selected CA, DNS identity and namespace before sending
the credential. Numeric dial address, DNS name, CA, namespace and full local
context bind the persistent queue; rotating the token does not redirect old jobs.
`emit_acceptance` separately authorizes host-generated recipient receipts, even
when the agent's own message permission is read-only.

`initial_cursor` is the relay position immediately before the first ciphertext
this admitted device can process. For a new empty mailbox it is zero (also the
omitted-field default). A fresh member joining an existing mailbox needs the
position supplied by trusted admission alongside its authenticated checkpoint;
never learn it by accepting an unauthenticated relay suggestion. This explicitly
excludes pre-join history, which the new MLS state may be unable to decrypt.
The full context and starting position bind the new queue/scan. Changing it on
retained state refuses; an application error never advances past an unknown item.

Initialize a never-used delivery destination once:

```sh
vhalla private delivery-init /absolute/account /absolute/room \
  --config /private/config/delivery.json
```

Add `--delivery /private/config/delivery.json` to the MCP server's command. The
host performs bounded ticks between RPCs, using one absolute network budget;
outage/backpressure preserves exact encrypted jobs with finite persisted retries.
Incoming pages and locally applied results remain private and durable. Dedicated
contact bootstrap needs its explicit commands; the driver does not invent join
authority. Malformed/uncertain kernel input or changed membership ends the grant
and preserves evidence for operator reconciliation.

A rejected relay credential ends the current agent process and grant. The exact
queued item, charged attempt and backoff remain in place; denial does not renew
budgets or change the endpoint binding. After the trusted operator corrects the
selected token file, wait for the retained backoff and prepare a new explicit
one-use grant. Reopening that same delivery profile then retries the original
ciphertext. Reusing the consumed grant still refuses. Malformed receipts and
exhausted lifetime retry budgets remain stopped for inspection.

`private_outbox_status` reports local queueing, optional relay retention, and
verified recipient-device claims separately. A device claim authenticates the
device's signed assertion about one exact ciphertext after local processing;
it is not proof of its physical disk, a human reading, current membership or
independent replication. Ordinary messages cannot promote delivery status.

Queue limits include completed and stopped jobs. Exhaustion never prunes evidence
or renews a stopped job. Preserve all persistent directories on failure and
restart; an archive, empty replacement queue, or new claim cannot safely erase
uncertain prior effects. Coherent rollback by the privileged host is outside this
local custody model.
