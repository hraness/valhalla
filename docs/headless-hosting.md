# Keep a participant-operated host online

An existing Linux machine can keep a public room's signed history available or
store encrypted private-room messages while participants are offline. These
are separate services; run either one or both.

**In development.** This recipe follows the source CLI. It has not been
validated as a deployment on your host or cloud provider. Complete the checks
below before relying on its availability.

## Prepare the machine

Use a Linux account with persistent writable disk, an available systemd user
manager, `jq`, and `openssl`. Build the CLI using the
[daemon guide](headless-daemon.md), then place its regular executable at a
stable absolute path. Use paths without symlinks, spaces, or shell expansion
characters. The published installer may contain an earlier CLI without the
daemon; check the release's documented features before using it.

```sh
umask 077
export VHALLA_BIN=/ABSOLUTE/STABLE/vhalla
install -d -m 700 "$HOME/.local/share/valhalla-host"
export VHALLA_HOST_ROOT="$(cd "$HOME/.local/share/valhalla-host" && pwd -P)"
export VHALLA_DAEMON_HOME="$VHALLA_HOST_ROOT/public"
export VHALLA_RELAY_URL=https://use1-1.relay.n0.iroh.link.
```

The relay above is the third-party Iroh relay selected by the current private
host default. Choose a different compatible HTTPS relay if needed. Keep that
choice across service installation and restarts.

User services require a running user manager. On a server that must work after
logout, its operator must enable lingering for this account, for example with
`loginctl enable-linger USERNAME`, subject to the machine's permissions.
Valhalla does not enable lingering. A container without a systemd user manager
can run the foreground command under its own supervisor, with the same stable
state directory; the managed-service commands will not work there.

## Publish a public read replica

Start with a new daemon home. Initialization creates a fresh account and peer
identity. Do not copy a participant's live account or room directory onto the
host.

```sh
"$VHALLA_BIN" daemon init --home "$VHALLA_DAEMON_HOME"
"$VHALLA_BIN" daemon run --home "$VHALLA_DAEMON_HOME" \
  --bind 0.0.0.0:48888 --relay-url "$VHALLA_RELAY_URL"
```

Leave it running. In another terminal, restore the variables above. Obtain a
`public.link` from a participant that retains the desired history, and verify
its room pin with the owner through a trusted channel. Replace both values:

```sh
export VHALLA_PUBLIC_LINK='valhalla://public/1/REPLACE_WITH_COMPLETE_LINK'
export VHALLA_VERIFIED_PIN='REPLACE_WITH_VERIFIED_64_CHARACTER_PIN'
mkdir -m 700 "$VHALLA_HOST_ROOT/public-requests"
cd "$VHALLA_HOST_ROOT/public-requests"

call_saved() {
  cat "$1" | "$VHALLA_BIN" daemon call --home "$VHALLA_DAEMON_HOME" |
    jq -e 'if .ok then .result else error(.error.message) end'
}

jq -n --arg link "$VHALLA_PUBLIC_LINK" \
  '{op:"public.inspect_link",link:$link}' > inspect.json
call_saved inspect.json > inspected.json
jq -e --arg pin "$VHALLA_VERIFIED_PIN" \
  'if .pin == $pin then . else error("Room pin differs") end' \
  inspected.json > selected-link.json
```

Stop if any command fails. The next commands save each operation before
submitting it. After a lost response, rerun `call_saved` with the same saved
request; do not regenerate its operation ID.

```sh
jq --arg operation "$(openssl rand -hex 16)" \
  '{op:"room.join_public",operation:$operation,genesis:.genesis,pin:.pin,
    limits:{max_records:100000,max_record_bytes:67108864}}' \
  selected-link.json > join.json
call_saved join.json > joined.json
```

After a successful join, publish and select the source:

```sh
export VHALLA_ROOM="$(jq -er '.room' joined.json)"
jq -n --arg room "$VHALLA_ROOM" --arg operation "$(openssl rand -hex 16)" \
  '{op:"public.publish",room:$room,operation:$operation}' > publish.json
call_saved publish.json > published.json

jq --arg room "$VHALLA_ROOM" --arg operation "$(openssl rand -hex 16)" \
  '{op:"public.source",room:$room,operation:$operation,source:.source}' \
  selected-link.json > source.json
call_saved source.json > source-selected.json

jq -n --arg room "$VHALLA_ROOM" \
  '{op:"public.sync_status",room:$room}' > sync-status.json
call_saved sync-status.json
jq -n --arg room "$VHALLA_ROOM" \
  '{op:"public.link",room:$room}' > host-link-request.json
call_saved host-link-request.json > host-link.json
```

Share the `link` from `host-link.json`. Clients verify the same room pin, then
follow the [public join flow](headless-api.md#public-join-and-source-flow) using
the host as their source. Joining creates a local author but does not authorize
it to send. Keep that author out of the owner's writer list for this read
replica. The room's existing owner remains responsible for writer admission;
hosting does not replace its signing state or give the host owner powers.

The host follows only its selected sources. If the source lacks another
writer's history, arrange for that writer's messages to reach the source or
select an additional source. There are at most eight selected sources per room.

## Install and verify the public service

Stop the foreground daemon and wait for that process to exit. Then install
with the same executable, home, and listener settings:

```sh
"$VHALLA_BIN" daemon stop --home "$VHALLA_DAEMON_HOME"
# Wait for the foreground terminal to return before continuing.
"$VHALLA_BIN" daemon managed install --home "$VHALLA_DAEMON_HOME" \
  --bind 0.0.0.0:48888 --relay-url "$VHALLA_RELAY_URL"
"$VHALLA_BIN" daemon managed status --home "$VHALLA_DAEMON_HOME"
"$VHALLA_BIN" daemon status --home "$VHALLA_DAEMON_HOME"
```

Managed status should report `result.service.installed:true`,
`unit_matches:true`, `state:"active/running"`, and a live `pid`. An unavailable
manager or successful installation alone does not establish network service.
Daemon status must also succeed. It reports the account and
`result.network.peer`; keep these values and the room pin for restart checks.
Supervisor output goes to `supervisor.log` inside the daemon home.

Complete these checks from another machine:

1. Wait for the host's `public.sync_status` to show the selected source's
   `verified.coverage:"complete"`. Read `room.messages` and identify a known
   signed message. Completion covers the stated source checkpoint, not all
   peers or future messages.
2. Have a separate client join and follow the host's link, then read that same
   message. If the original source is temporarily offline, the host should
   still serve history it has already saved.
3. Stop the host with `daemon stop`, wait until managed status has no live PID,
   and let an authorized participant publish another message to the selected
   source. Repeat the exact managed-install command to start the host again.
   Check the account, peer identity, and pin are unchanged, earlier messages
   remain readable, and the new message arrives after synchronization.

A clean stop is not automatically restarted by the generated service. It
restarts unsuccessful exits. Inspect status and logs before retrying a failed
installation; never remove state to make a refusal disappear.

## Host a private Iroh mailbox

Use a separate new home. This mailbox stores ciphertext and needs no room
owner account or MLS room keys. The command selects the same stable binary
for later service installation:

```sh
export VHALLA_MAILBOX_HOME="$VHALLA_HOST_ROOT/private-mailbox"
"$VHALLA_BIN" private-host init "$VHALLA_MAILBOX_HOME" \
  --transport iroh --relay-url "$VHALLA_RELAY_URL" --executable "$VHALLA_BIN"
"$VHALLA_BIN" private-host serve "$VHALLA_MAILBOX_HOME"
```

From another terminal, run:

```sh
"$VHALLA_BIN" private-host status "$VHALLA_MAILBOX_HOME" --probe
```

Check `probe.probed:true`. This is an authenticated mailbox check from the host
machine. It does not establish access from a participant's network.

Keep the entire home, including `endpoint.key`, `connection.json`, mailbox
data, sealed configuration, and token files. Give each participant only
`namespace` and `endpoint` from `connection.json` plus its own `client-N.token`
through a private channel. Initialization supplies two credentials; use
`private-host add-credential HOME` for another participant, then drain and
restart the host to activate it. Never share `endpoint.key` or give all
participants one token. Use a separate mailbox for unrelated rooms.

Members follow the [private contact and delivery-profile
instructions](headless-api.md#private-contact-and-delivery-profile). Each uses
its own private profile and local queue directory. The mailbox token grants
transport access; room admission still requires the owner's contact exchange.

After the foreground check, stop the host with Ctrl-C and wait for it to exit:

```sh
"$VHALLA_BIN" private-host install "$VHALLA_MAILBOX_HOME"
"$VHALLA_BIN" private-host status "$VHALLA_MAILBOX_HOME" --probe
```

Check the reported systemd service state as well as the probe. Logs live in
`supervisor.log`; lifecycle events are in `events.log`. From another machine,
send a test message between admitted members using this mailbox. Confirm
mailbox retention in `private.delivery_status`, then confirm the recipient
reads it and its device acceptance appears in the sender's
`room.outbox_status` reply under `result.records[].device_acceptances`.

To check offline delivery, stop the recipient daemon, send another message,
and wait for the sender's queue to report `retained`. Drain and restart the
mailbox using `private-host uninstall HOME` followed by `private-host install
HOME`. Its home and logs remain. Restart the original recipient daemon and
check it receives the saved message. Do not recreate profiles or queues during
this check. The [Iroh guide](iroh-private-rooms.md) covers routing and credential
maintenance in more detail.

## Network, disk, and upgrades

Direct connections use UDP. The public example binds UDP port 48888; permit it
in the host and provider firewall if you want direct access. A wildcard bind
is not a public address or a NAT forwarding rule. The configured HTTPS Iroh
relay provides another route; it forwards encrypted traffic and does not store
room history. The private mailbox is the separate service that stores
ciphertext. An HTTP reverse proxy alone does not provide either UDP service.
Owner commands and MCP use local sockets. Administer the host through its local
CLI or SSH; keep its control directory and administrative capability private.
The earlier [TLS container recipe](local-host.md#a-hosted-container) uses a
different transport and does not establish a provider's Iroh or UDP support.

Public relay-only operation requires `--relay-only` together with `--relay-url`
when running and installing the daemon. Choose it before the first managed
installation. Private clients select `transport.relay_only:true` in their
Iroh delivery profiles separately. A relay-configured private host requires
its relay to be reachable at startup. See the Iroh guide for a direct-only
host with `--relay-url none` and a fixed reachable `--iroh-bind` address.

Keep state on disk that survives process, container, and machine restarts.
Monitor filesystem free space, `room.status`, `public.sync_storage`, mailbox
directory size, and logs. Payload quotas exclude some database and filesystem overhead.
The [API limits](headless-api.md#status-limits-and-recovery) distinguish stores
that can grow from fixed quotas. Retained private ciphertext continues to use
storage. Hosting may charge for compute, persistent disk, backups, and network
egress. Check your provider's current limits and pricing; this recipe assumes
no free tier or unlimited traffic.

For an upgrade, first choose a binary documented as compatible with the saved
state. Stop installed services with `daemon managed uninstall --home HOME` or
`private-host uninstall HOME`, and confirm they have stopped; stop any
foreground process too. Preserve the whole stopped homes and external
client profiles, tokens, certificates, and queues. Replace only the executable
at its selected stable path, then reinstall with the same home and options.
Do not move or recreate the daemon home, edit its managed selection, or run two
processes against copied signing state. Repeat the availability and restart
checks after the upgrade. If the new binary refuses the state, preserve it and
resolve compatibility instead of resetting it. Saved snapshots are historical
copies, not permission to reactivate an old signing or MLS state.
