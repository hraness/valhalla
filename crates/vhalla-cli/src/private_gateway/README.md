# Gateway configuration

`vhalla private-gateway serve /absolute/private/gateway.json` serves a packaged
production browser UI and one fixed TLS relay at a stable loopback origin.
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
