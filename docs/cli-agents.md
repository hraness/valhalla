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

The grant is validated at launch and durably consumed once — immediately before
the first `tools/call` or, with `--delivery`, the first driver tick — even if
the process later exits cleanly. Handshakes, tool listings and inventory probes
alone never burn the grant, but once consumed an automatic reconnect with the
same grant refuses. Preserve
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

To poll a quiet mailbox more often, add `"mailbox_polling": "interactive"`
before the first `delivery-init`. This mode waits five seconds after an empty
scan, or one second for 30 seconds after newly queued or observed work. The
default, `"adaptive"`, waits 10, 20, then at most 30 seconds after successive
empty scans. Interactive mode trades up to six times as many steady idle TLS
exchanges for a shorter wait to discover incoming messages. These intervals
exclude scheduler, network and processing time; they are not delivery deadlines.
Network errors retain their separate retry delay in both modes.

The polling choice binds the delivery state. Editing it after initialization
refuses; there is no in-place policy migration. Omitting the field preserves the
adaptive profile format. Older binaries reject the interactive field before
networking. Do not recreate a queue to change its policy or regain allowance.

`initial_cursor` is the relay position immediately before the first ciphertext
this admitted device can process. For a new empty mailbox it is zero (also the
omitted-field default). A fresh member joining an existing mailbox needs the
position supplied by trusted admission alongside its authenticated checkpoint;
never learn it by accepting an unauthenticated relay suggestion. This explicitly
excludes pre-join history, which the new MLS state may be unable to decrypt.
The full context and starting position bind the new queue/scan. Changing it on
retained state refuses. A staged item the kernel proves can never apply —
stale, foreign, malformed or otherwise terminally unprocessable — receives a
durable bounded skip marker so the applied watermark still advances past it.

Initialize a never-used delivery destination once:

```sh
vhalla private delivery-init /absolute/account /absolute/room \
  --config /private/config/delivery.json
```

Initialization publishes a version-2 selected profile after the control queue
is durable. To opt an existing version-1 delivery state into encrypted-control
forwarding, stop its agent and use the same account, room and profile:

```sh
vhalla private delivery-upgrade /absolute/account /absolute/room \
  --config /private/config/delivery.json
```

The upgrade is additive and recoverable: it retains the original queue, exact
ciphertexts, watermarks and attempts, then atomically advances the selected
profile version. An old binary refuses that version before networking. Never
restore an old profile to bypass this refusal. The new control queue has the
same configured finite limits as the outbox queue, independently: total retained
item bytes across both are bounded by twice `max_bytes`, plus storage metadata
and incoming evidence. Inspect available storage before this explicit upgrade.
Repeating an upgrade on an already selected v2 profile validates its existing
control evidence; it refuses a missing queue or activation marker. Preserve
those files for reconciliation rather than recreating them.

Add `--delivery /private/config/delivery.json` to the MCP server's command. The
host performs bounded ticks between RPCs, using one absolute network budget.
Transient connect, timeout and unavailable outcomes keep a job live with its
own backoff without spending the finite definitive-refusal retry budget.
A definite remote relay-capacity refusal does charge an attempt and eventually
stops at that configured limit, as do other definitive outcomes such as denial,
conflict or malformed responses. Local queue capacity instead defers enqueue
while preserving committed work. None of these outcomes creates new allowance.
Incoming pages and locally applied results remain private and durable. Dedicated
contact bootstrap needs its explicit commands; the driver does not invent join
authority.

Existing members automatically forward only exact encrypted owner controls
from authenticated retained history to this explicitly selected pinned relay.
The two outgoing streams merge by authenticated epoch: older local applications
precede their owner's next control; newer applications wait for their required
controls. Independent remote membership changes can still make unsent old-epoch
traffic stale. A real membership change invalidates the current grant and
requires a fresh roster-bound grant; exact duplicate controls do not.
Acceptance issuance commits to the same durable outbox and waits for monotone
capture before transport. A legacy queue containing an unresolved item beyond
its captured frontier refuses before networking, preserving bytes and attempts
for reconciliation. A normal interrupted enqueue of the next item can still
reconcile exactly and continue.

The driver persists its outgoing and applied watermarks in the durable queue
and revalidates restored applied markers in bounded passes against exact staged
items and authenticated kernel history. It preserves the old durable checkpoint
while verification catches up; marker filenames alone never justify progress.
Revalidation does not encrypt a replacement, issue a new acceptance or apply an
unseen control. Mailbox polling follows the selected policy and repolls on the
next tick when a page still has staged work; network errors back off separately (1s to 30s)
without touching staged evidence. There is no lifetime poll cap: a quiet room
never silently exhausts its driver's attention. A staged item whose kernel
outcome stays transient for five minutes, storage or custody uncertainty, or
changed membership ends the grant and preserves evidence for operator
reconciliation; terminal item-local failures record a skip marker instead.

Inspect the durable delivery journal without consuming a grant:

```sh
vhalla private delivery-status /absolute/account /absolute/room \
  --config /private/config/delivery.json --out /private/config/status.json
```

The report lists retained job rows (`pending`, `uncertain`, `retained`,
`stopped`) with charged attempts and the durable driver watermarks. It opens
queue custody under its own lock, makes no network contact and emits no keys,
plaintext or ciphertext; run it while no agent holds the profile's custody.
Add `--stream control` to inspect the separate encrypted-control queue;
`--stream outbox` is the default. Both reports retain their own charged work.

A rejected relay credential ends the current agent process and grant. The exact
queued item, charged attempt and backoff remain in place; denial does not renew
budgets or change the endpoint binding. After the trusted operator corrects the
selected token file, wait for the retained backoff and prepare a new explicit
one-use grant. Reopening that same delivery profile then retries the original
ciphertext. Reusing the consumed grant still refuses. Malformed receipts and
exhausted lifetime retry budgets remain stopped for inspection.

A stopped job is re-armed explicitly, never implicitly:

```sh
vhalla private delivery-resume /absolute/account /absolute/room \
  --config /private/config/delivery.json [--stream outbox|control] [--job DIGEST64]
```

Without `--job` it re-arms every stopped job in the queue; with it, exactly one
job id. Re-arming keeps every spent attempt, outage count and resume count as
durable evidence — it never rewrites ciphertext, recreates the queue, or resets
the original operation. The job then waits its normal backoff under the next
delivery-capable process.

`private_outbox_status` reports local queueing, optional relay retention, and
verified recipient-device claims separately. Its optional `wait_for` argument
(at most 25 seconds) turns the call into a long poll that answers on changed
evidence, timeout, or immediately when no delivery driver could change anything.
A refused TCP connect reports `unreachable`, distinct from `uncertain`, where
retained bytes may have reached the relay before the outcome was lost. A device
claim authenticates the device's signed assertion about one exact ciphertext
after local processing; it is not proof of its physical disk, a human reading,
current membership or independent replication. Ordinary messages cannot promote
delivery status. Device-to-device acceptance receipts are filtered out of
`private_inbox` records and refund their read slots; they only surface through
`member_acceptances`. A spec-shaped `notifications/cancelled` naming a pending
request id drops only that wait; stale or unknown ids are ignored, and room
content is never cancellation or any other authority.

The live-job count includes pending, uncertain and stopped jobs. Retained jobs
remain in history and consume the lifetime retained-byte allowance. Exhaustion
never prunes evidence or renews a stopped job. Preserve all persistent directories on failure and
restart; an archive, empty replacement queue, or new claim cannot safely erase
uncertain prior effects. Coherent rollback by the privileged host is outside this
local custody model.
