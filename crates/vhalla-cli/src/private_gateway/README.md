# Gateway configuration

`vhalla private-gateway serve /absolute/private/gateway.json` serves a packaged
production browser UI and one fixed TLS relay. Format 1 uses a stable loopback
HTTP origin. Format 2 uses direct HTTPS for browsers without a local gateway.
Run it as a separate foreground process alongside the TLS host. It connects as
a TLS client and never opens a second mailbox writer. The host's LaunchAgent
manages the relay only; it does not start the browser gateway.

Lifecycle commands take the same canonical absolute config path:

- `vhalla private-gateway status CONFIG` reports the validated configuration,
  the deterministic `me.vhalla.private-gateway.<path-digest>` label, launchd
  state and the sibling bounded `events.log`. `status --probe` additionally
  performs a real bounded loopback HTTP GET for format 1 and reports whether the listener
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

The format 1 browser profile requires the exact numeric host `127.0.0.1`. Choose a fixed
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

## Direct HTTPS configuration

Format 2 accepts a canonical HTTPS DNS origin and terminates TLS in the gateway.
The browser uses its normal certificate trust. Use a certificate for the selected
DNS name and include its DER chain, leaf first, with the matching PKCS#8 DER key.
The upstream relay still uses the exact configured CA, server name, namespace
and independent token. Browser profiles never include upstream credentials.

This is an explicit experimental transport option. Hosted operation still needs
certificate renewal, deployment recovery, monitoring and independent browser
qualification before activation. A configuration that loads successfully does
not establish those results.

```json
{
  "format": 2,
  "listen": "0.0.0.0:8443",
  "origin": "https://rooms.example.com:8443",
  "namespace": "<64 lowercase hex characters from the selected relay host>",
  "tls": {
    "certificate_chain_files": ["/private/gateway/leaf.der", "/private/gateway/intermediate.der"],
    "private_key_file": "/private/gateway/key.der"
  },
  "clients": [{
    "id": "<32 lowercase hex characters, nonzero and unique>",
    "token_file": "/private/gateway/browser-client-1.token",
    "expires_unix_secs": 0,
    "revoked": false,
    "max_inflight": 2,
    "requests_per_window": 64,
    "bytes_per_window": 16777216
  }],
  "upstream": {
    "addr": "127.0.0.1:8788",
    "tls_name": "relay.local",
    "tls_ca_file": "/private/gateway/upstream-ca.der",
    "token_file": "/private/gateway/upstream.token"
  },
  "assets_dir": "/absolute/packaged-production-ui",
  "initial_cursor": "0"
}
```

The zero expiry in this example is inactive. Set an explicit UNIX-seconds expiry
at most seven days after startup for an active client. There is no automatic
renewal. A running gateway checks wall-clock expiry and a monotonic deadline
derived at startup; once observed expired, the client stays denied. Accurate
host time at startup remains an operating requirement.

One instance serves one namespace through one fixed upstream credential. It
accepts one through 64 browser client entries. IDs and nonzero 256-bit tokens
must be distinct, including revoked entries. A browser token cannot equal the
upstream token. An expired or revoked client receives a refusal while other
valid clients remain usable. To revoke or rotate a client, stop and drain the
gateway, update that client's entry, and restart. Existing requests are drained
under their original deadlines; editing a file does not change a running process.

The origin accepts lowercase ASCII DNS labels and an optional nondefault port.
It refuses IP literals, shortened IPv4 spellings, localhost, credentials, paths,
query strings, fragments, trailing dots, uppercase names and explicit port 443.
The effective origin port must equal the listener port. Choose the permanent
origin before retaining a browser profile; a changed origin cannot reinterpret
existing browser state.

Connections require TLS 1.3 and HTTP/1.1 ALPN. The TLS server name and HTTP Host
must match the configuration exactly. Relay POST requests additionally require
the exact Origin, namespace and bearer token. Forwarded and X-Forwarded headers
are refused. There is no proxy-header trust setting or plaintext fallback.
Unauthenticated asset GETs use only the verified production manifest allowlist.

The gateway admits at most eight concurrent connections, 128 accepted connections
and 64 MiB of request/response bodies per 10-second window. TLS handshakes have a
three-second limit within the original 10-second request deadline. At capacity,
HTTPS connections close without sending plaintext HTTP. Each client additionally
has one through eight concurrent requests, one through 4,096 requests per window,
and at most 64 MiB of admitted browser request/reply frames per window. A reply
can be read from the upstream before its size is checked against the remaining
client budget. If it does not fit, the gateway sends HTTP 429 without a relay
receipt; the request charge remains and the rejected reply is not charged.
These byte limits do not cap all upstream traffic. Request counts, concurrency,
the relay's maximum response size and the original deadline bound that work.
Failed requests keep charges already incurred. These in-memory limits restart with the
process; the upstream mailbox and credential quotas remain retained. All browser
clients share those existing upstream quotas.

Expiry is checked again after reading a request body and before contacting the
upstream. A response limit or connection failure after a PUT can still leave
retention uncertain. Keep the committed ciphertext and retry its exact bytes
under valid authority. Successful retention remains distinct from recipient
acceptance.

`status --probe` for format 2 checks TCP connectivity only and reports
`probed: false`. It does not send plaintext HTTP to the TLS listener or claim
certificate validation. Verify the selected DNS name and ordinary browser trust
separately from upstream relay health. Format 1 keeps its existing loopback HTTP
probe and configuration unchanged.
