# Gateway configuration

`vhalla private-gateway serve /absolute/private/gateway.json` serves a packaged
production browser UI and explicitly configured TLS relays at a stable loopback origin.
Run it as a separate foreground process alongside the TLS host. It connects as
a TLS client and never opens a second mailbox writer. The host's LaunchAgent
manages the relay only; it does not start the browser gateway.

Lifecycle commands take the same canonical absolute config path:

- `vhalla private-gateway status CONFIG` reports the validated configuration,
  the deterministic `me.vhalla.private-gateway.<path-digest>` label, launchd
  state and the sibling bounded `events.log`. `status --probe` additionally
  performs a real bounded loopback HTTP GET and reports whether the listener
  answered `HTTP/1.1 200`; a probe proves listener shape only, never upstream
  TLS or mailbox retention.
- `vhalla private-gateway install CONFIG` validates the full configuration,
  writes the exact plist for that one label into `~/Library/LaunchAgents` and
  bootstraps it. A foreign or changed plist at the label refuses; the command
  never lists or touches other services in the GUI domain.
- `vhalla private-gateway uninstall CONFIG` boots out only the exact label when
  the loaded service identifies the owned plist, then removes the plist file.
- `serve` retries a transient address-in-use bind for a bounded window, logs
  `serve-start`/`bind-retry`/`serve-stop` to the bounded `events.log` beside
  the config, and drains SIGTERM/SIGINT before exit.

An unwinding connection-local handler panic closes that request without a
success response. The gateway continues only when the shared admission budget
is unpoisoned and the panic occurred outside the upstream TLS exchange. Failed
requests retain their admission charges; isolation does not reset limits.
A poisoned shared budget, a panic during upstream exchange, an unexpected
worker failure or inability to spawn a worker stops admission and drains the
already-admitted workers under their original deadlines, then exits with
failure. The gateway never repairs or clears poisoned state in place. Ordinary
upstream timeout/unavailable responses remain request failures and may have an
uncertain retention outcome; clients retry the same committed ciphertext.
A connection failure after upstream publication likewise does not prove that
the PUT was absent, even when the gateway isolates the failed handler.
This boundary covers unwinding panics, not process aborts or unhealthy-disk
guarantees. Core fault tests exercise the shutdown flag. The CLI lifecycle
regression sends real SIGTERM while an admitted HTTP PUT is waiting for its
final body byte, completes that request through the real TLS host during drain,
then restarts both processes and checks exact duplicate retention at the same
origin. It uses synthetic local custody and assets; it does not inject a signal
inside an upstream filesystem barrier or qualify launchd supervision.

The bounded 0600 configuration file and credential/CA files must have 0700 parent
directories. All paths are absolute. Unknown fields refuse. Example structure
(values below are placeholders, never usable credentials):

```json
{
  "format": 1,
  "listen": "127.0.0.1:8790",
  "namespace": "<64 lowercase hex characters from the selected relay host>",
  "browser_token_file": "/private/host/browser-token",
  "upstream": {
    "addr": "127.0.0.1:8788",
    "tls_name": "relay.local",
    "tls_ca_file": "/private/host/ca.der",
    "token_file": "/private/host/gateway-upstream-token"
  },
  "assets_dir": "/absolute/packaged-production-ui",
  "initial_cursor": "0"
}
```

Tokens are independent nonzero 32-byte values encoded as canonical lowercase hex,
with at most one terminal newline. TLS uses the exact supplied CA/server name;
there is no ambient trust or plaintext fallback. Asset manifest purpose must be
`production`, every allowed file's size/hash must match, and the complete in-memory
allowlist is bounded to 64 files/64 MiB. Unlisted files cannot be served.

For a drained mailbox transition, format 2 adds a `retained` array containing
the predecessor routes. Each entry has exactly `namespace`,
`browser_token_file` and `upstream`, with the same shapes as the active fields.
Keep `listen` unchanged: moving the browser origin would select a different
IndexedDB store. The active route plus retained routes are limited to 16.
Each namespace and browser capability must be distinct. No browser capability
may equal any route's TLS credential.

Requests select only an enrolled namespace using the existing request header.
They cannot choose a destination, TLS name or redirect. All routes share the
gateway's connection, request and byte limits. The old TLS host retains its
permanent fence, allowing reads and exact already-stored retries while refusing
new items. Configuring a route does not migrate a browser profile or authorize
a generation change; the paused controller must complete that separately.

The current browser requires the exact numeric host `127.0.0.1`. Choose a fixed
non-default HTTP port; port 80 refuses because browser origins omit its explicit
port. For a remote client, forward the configured gateway port to the same local
loopback host and port; different client-local ports are refused by exact
Host/Origin checks. Keep this stable before retaining browser profiles.

The browser's imported connection file has `format`, `origin`, `namespace`,
`capability` and a canonical
decimal-string `initial_cursor` from 0 through the mailbox capacity of 4,096.
That cursor is an explicitly trusted enrollment
boundary, not permission to skip undecryptable retained history. Browser custody
binds it immutably with the full room context. The browser capability is supplied
again on every unlock and excluded from retained profile state; never put the TLS credential in the browser profile
or persist the browser capability to IndexedDB. `initial_cursor` in host config
records guidance for the matching browser profile; the gateway neither exports
a profile endpoint nor uses that field to authorize skipping history. Each HTTP
request carries its own cursor, and the browser enforces its retained cursor
binding. The gateway does not silently advance a cursor.

Neither an HTTP success nor relay retention is a human-read or member-acceptance
claim. Preserve committed ciphertext and retry exact bytes after an uncertain
response. Stop the host before explicit capability/configuration rotation.
