# Local private-room host

A mostly persistent Mac can host the opaque private relay. No paid cloud is
required. The native path is a CLI agent, a fixed local Tailcat forward, the
Mac's Tailcat server, and the loopback TLS mailbox. Both the TLS trust selection
and per-client relay authentication remain active through the overlay.

This command needs `experimental-private`. It never opens an account identity,
MLS room, archive, browser key, or menubar authority. The host stores bounded
opaque ciphertext. Relay retention is distinct from a recipient's signed claim
and does not prove that a person read a message.

## Create and inspect a host

Choose a stable, reviewed executable and a never-used directory. Its parent must
exist. The command creates the directory with mode `0700`; generated files are
owner-only `0600`. The default listener is `127.0.0.1:9473`; wildcard and remote
listeners are refused. The TLS name is a pinned certificate name and does not
need public DNS.

```sh
/absolute/vhalla private-host init /private/operator/valhalla-host \
  --listen 127.0.0.1:9473 --tls-name relay.valhalla.invalid \
  --executable /absolute/stable/vhalla
/absolute/vhalla private-host status /private/operator/valhalla-host
```

Initialization creates:

- A fresh random opaque namespace, two independent credential identities and
  `client-1.token` / `client-2.token` files containing canonical hexadecimal
  secrets. Assign different files to independently controlled clients.
- A directly issuing CA (`ca.der`), one TLS leaf (`server.der`), and separate
  PKCS#8 private keys. `ca-key.der` and `server-key.der` stay on the operator's
  private host. Clients receive only `ca.der` and their selected client token.
- An enrolled durable mailbox capped at 4,096 items and 256 MiB of payload. Each credential
  can retain at most 2,048 items and 128 MiB. Exhaustion refuses new items while
  preserving retained items and exact retries; there is no automatic deletion.
- Immutable `config.json`, a completion commitment, and exact file commitments.
  Partial initialization, changed selections, linked files, unsafe permissions,
  and existing homes refuse rather than being repaired or reset.
- A non-secret `connection.json` containing the namespace, local listen address,
  TLS name, CA fingerprint and expiry. It contains no client token or private key.
- A reviewable `launch-agent.plist` containing only the selected executable,
  exact canonical home, and bounded process supervision settings.

Keep the entire home, especially the mailbox and quota state, across restarts.
Never copy a live mailbox to reset quota or delete state to bypass a refusal.
If initialization fails, preserve its partial directory and diagnose it; rerunning
`init` on that path deliberately refuses.

## Foreground and login lifecycle

Run foreground first and verify TLS retention before enabling login startup:

```sh
/absolute/vhalla private-host serve /private/operator/valhalla-host
```

`SIGINT` and `SIGTERM` stop admission and drain admitted workers under their
original request deadlines before releasing mailbox custody. Filesystem barriers
are not forcibly interruptible; the service does not claim a hard deadline for
an unhealthy disk. Storage uncertainty exits with failure and requires an exact
reopen. Starting a second owner of the same mailbox refuses.

On macOS, the following commands manage only the per-user LaunchAgent whose
label is derived from this canonical home:

```sh
/absolute/vhalla private-host install /private/operator/valhalla-host
/absolute/vhalla private-host status /private/operator/valhalla-host
/absolute/vhalla private-host uninstall /private/operator/valhalla-host
```

Installation copies the exact reviewed plist to `~/Library/LaunchAgents`, then
uses `launchctl bootstrap` in the current user's GUI domain. It refuses another
loaded instance, unsafe ancestry, and foreign or modified plist contents.
Uninstallation verifies the exact loaded plist path, stops only that service,
and removes only its matching installed plist. Stop selection needs the intact
sealed configuration and exact template, but does not require readable TLS
credentials; damaged or missing credential files are preserved without repair.
The complete host home remains. A launchd query error is not treated as an absent
service: unexpected IPC, permission, domain or output failures preserve the
installed plist and refuse removal, including after an uncertain stop.
No command installs the menubar or changes another service.

The LaunchAgent starts at login, restarts unsuccessful exits with a 30-second
throttle, and has a 15-second exit grace. It does not promise service before
login, while logged out, or while the Mac sleeps. Its stdout/stderr go to
`/dev/null`, avoiding growing logs and accidental credential logging. Foreground
errors are deliberately coarse and contain no secrets. `status` reports loaded
service state separately from health: it performs no TLS exchange and never
opens mailbox writer custody. A loaded process is not successful live
qualification. Keep a stable executable path; there is no automatic updater.

## Explicit Tailcat wiring

Tailcat is a separate native process and must be installed and reviewed
independently. The following syntax was checked against the installed pinned
Tailcat **v0.7.0** source and command help. Its `serve` command accepts a bare
port and forwards to that port on localhost; later upstream mapped-port syntax
must not be copied into this pinned configuration.
([Tailcat v0.7.0 CLI source](https://github.com/tailscale/tailcat/blob/v0.7.0/cmd/tailcat/tailcat.go))

Use an explicit absolute key file, not an ephemeral `--key=new` or a platform-
dependent default key location. Generate it once without `--force`. Capture
its printed address through an owner-private channel: a Tailcat address is a
capability and does not belong in the non-secret connection descriptor, public
DNS, general logs, or source control.

```sh
/absolute/tailcat genkey \
  --key=/private/operator/valhalla-host/tailcat.private.json --fixed-region
/absolute/tailcat \
  --key=/private/operator/valhalla-host/tailcat.private.json \
  serve 9473
```

For a separately supervised overlay, generate a new reviewable template after
creating the saved key:

```sh
/absolute/vhalla private-host tailcat-plist /private/operator/valhalla-host \
  --binary /absolute/tailcat \
  --key /private/operator/valhalla-host/tailcat.private.json \
  --out /private/operator/valhalla-host/tailcat-agent.plist
```

This validates selected executable/key/output file custody, maps only the relay's
one configured bare TCP port, requires the relay to bind exactly `127.0.0.1`,
uses a distinct `.tailcat` label and a 30-second restart
throttle, and discards stdout/stderr rather than logging its capability address.
It neither interprets the private-key format nor executes, installs or starts
Tailcat. The selected Tailcat version must validate its own saved key at actual
activation. Existing outputs and linked/unsafe key files refuse without mutation.
Review and install the overlay plist separately; the relay's `uninstall` command
does not remove the independently managed overlay service.

On each client, select one fixed local forwarding port:

```sh
/absolute/tailcat forward --bind=127.0.0.1 PRIVATE_TAILCAT_ADDRESS 19473:9473
```

The client's [delivery profile](cli-agents.md#local-hosting-and-persistent-tls-delivery)
then uses `127.0.0.1:19473`, the exact TLS name, transferred `ca.der`, selected
namespace and its own token file. The listener address in `connection.json` is
the host-side address; it is not automatically a remotely reachable endpoint.
Keep the client port fixed because it is part of the persisted endpoint binding.
Do not use Tailcat's `all`, `exit-node`, SSH, file or exec services for this relay.
Tailcat startup and supervision are deliberately separate from the relay's
LaunchAgent; these commands do not silently install or activate the overlay.

Stop/restart the exact Tailcat process with the same saved key. Tailcat server
termination is process-level; the native relay preserves custody independently.
The forward command handles `SIGINT`/`SIGTERM` and closes its listeners and
connections. Do not use its address-file output on a pre-existing linked path.

The actual v0.7.0 restart qualification found that a surviving client forward
did not reconnect after the server restarted: eight bounded exact retries
timed out. Stop that selected client forward and start it again with the same
address and fixed local port. This recovered immediately in the synthetic TLS
journey, retaining the same mailbox, certificate, credential and ciphertext;
the retry returned the original position as a duplicate. Do not regenerate the
server key or clear queue/scan state to recover. Automatic forwarding recovery
across server restart is not qualified. Browser users must likewise preserve
their gateway's fixed origin port when restarting the forward.

A sleeping/offline Mac delays delivery. Durable native clients retain exact
ciphertext and bounded retry state. Restarting an MCP session still needs a new
explicit one-use host grant; waking the relay never renews agent authority.

## Browser sessions

Use the released production browser archive with the
[gateway configuration](../crates/vhalla-cli/src/private_gateway/README.md) and
the [browser connection guide](../browser/README.md#explicit-local-host-private-sync).
Start `vhalla private-gateway serve /absolute/private/gateway.json` alongside
the relay. The gateway receives one relay credential and a separate random
browser capability; the browser receives only its own connection profile and
capability. Keep its chosen loopback origin stable across sessions.

On this Mac, open that gateway's local URL directly. For a browser on another
machine, either run its own gateway over the forwarded TLS connection, or serve
the gateway's one port through Tailcat and forward to exactly the same local
port on the browser machine. The generated relay Tailcat plist serves only the
relay port; it does not silently enable the browser port. The relay LaunchAgent
also does not supervise the gateway. A closed gateway or suspended browser pauses
delivery; reopen the exact retained connection and choose **Sync now** to resume.

## Expiry and qualification boundaries

The leaf is valid for 365 days, the CA for five years, with a five-minute clock
skew allowance at creation. Status reports leaf expiry; serving an expired or
not-yet-valid selection refuses. There is no automatic certificate renewal in
this command. The retained CA key permits a future explicitly reviewed same-CA
renewal. Preserve the CA, namespace and client endpoint: replacing those changes
delivery binding. Do not edit committed file hashes or create a new mailbox to
bypass expiry; certificate publication/renewal requires its own bounded operator
workflow before expiry. Existing profiles remain compatible with the unchanged
CA/name/address and retained state.

Local tests cover generated custody, distinct credentials, finite certificates,
TLS retention, wrong credentials, concurrent-owner refusal, read-only status,
SIGTERM drain, exact retry after restart, and malformed/partial-home refusal.
An actual pinned v0.7.0 Tailcat server/forward on this Mac also passed TLS
retention, exact scan, host outage refusal and explicit client-forward restart
recovery. The receipt is
`/private/tmp/valhalla-tailcat-live-20260922-r3/receipt.json`; all task processes
were stopped afterward. This used synthetic opaque transport data, not two
physical machines. Login activation, sleep/wake and browser delivery have
separate evidence requirements. A browser cannot call this custom TLS protocol
directly; its [gateway/worker integration](../browser/README.md) supplies that
path. No paid host or public DNS is required for the local workflow.
