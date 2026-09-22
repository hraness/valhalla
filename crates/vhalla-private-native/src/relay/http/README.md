# Loopback browser gateway

The gateway forwards to exactly one preconfigured `TlsRelay`. It never opens a
mailbox, holds MLS keys, chooses a user-provided upstream URL, follows redirects,
or interprets an upstream retention receipt as member acceptance.

`Gateway::new` requires a nonzero fixed loopback port, the TLS client's exact
namespace and an independent browser capability. Reusing the TLS token as that
capability refuses before dialing. Stable origin is `http://127.0.0.1:PORT` (or
an explicitly configured numeric IPv6 loopback address). There is no CORS mode.
Every request must have that exact Host; an Origin, when present, must match.
A remote client using a Tailcat/SSH loopback forward must use the same configured
loopback host and local port as the gateway origin. A different forwarded local
port intentionally refuses; configure a stable matching port before retaining
profiles. An arbitrary Origin override is not supported.

Browser calls use `POST /private-relay/v1` with:

- `Origin`: the exact configured origin, supplied by the browser;
- `Authorization: Bearer ` followed by 64 lowercase hex capability characters;
- `X-Vhalla-Namespace`: 64 lowercase hex namespace characters;
- `Content-Type: application/octet-stream` and one canonical Content-Length;
- one portable v1 frame, with PUT's canonical item or PAGE's cursor/limit body.

The browser never receives the upstream TLS token. HTTP framing excludes a relay
token: the gateway adds its own credential only after TLS server authentication.
Duplicate headers, transfer/content encodings, oversized headers/body, unknown
operations, malformed items/pages, wrong namespace, Host or Origin refuse before
upstream calls. Successful HTTP responses contain one canonical relay status
frame; generic HTTP 400/403/408/429 responses carry no credentials or ciphertext.
No request headers or tokens are logged.

Eight concurrent requests, 128 admissions per ten-second monotonic window and
64 MiB of request/response bodies per window are defaults. Each complete request,
including the upstream exchange and response write, has a ten-second deadline.
The policy has finite hard maxima. Stopping admission drains admitted workers
under their existing deadlines; no detached gateway workers remain. These are
resource bounds, not a promise of availability against a hostile local process.
TLS relay storage and per-credential quotas remain independently enforced.

GET serves only immutable assets preloaded from a verified production manifest;
there is no path lookup during requests, fallback directory serving or secret
profile endpoint. The UI uses CSP, no-store, nosniff and same-origin opener policy.
The CLI refuses qualification artifacts and known qualification entry points.
Browser capability is a host-level credential supplied afresh to each unlocked
worker and retained only in worker memory. Rotation requires explicitly stopping
the host and replacing configuration. No per-worker revocation is claimed.

Regression tests cover rejected auth/origin/Host/namespace/framing without an
upstream call, canonical receipts and unavailable statuses, static allowlists,
slow headers, idle shutdown, finite policy and token separation. Real-browser
transport and persistent-host qualification are separate integration journeys.
