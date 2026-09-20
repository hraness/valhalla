# Public peer reads and optional route discovery

This native Unix crate serves canonical advertisements, independently pinned
bootstrap artifacts, and bounded pages of locally published journal bundles.
The default service is READ-only. An explicitly enabled discovery registry also
accepts bounded signed route registrations. Neither mode grants room membership
or validator admission, writes the consensus journal, or starts implicitly.
Public activity requires the separate explicit `ManagedPeer::create_with_activity`
or `open_with_activity` API. Ordinary `create`, `open` and the existing READ CLI
remain READ-only. No activity service starts implicitly.

`Peer::open(Config)` bounded-reads and validates an independently supplied
bootstrap file and full pin, derives its genesis frontier, opens an existing
custody identity, and verifies the operator's retained signed advertisement.
The advertisement must name that complete application key, immutable network
origin, READ capability, and exactly the explicitly configured HTTPS endpoint.
`Arc<Peer>::bind()` accepts only a loopback address (default recommendation
`127.0.0.1:9790`). `BoundPeer::run(shutdown)` owns the listener lifetime.

The operator must configure a TLS reverse proxy for that exact advertised
endpoint, ending in `/vhalla/v1`. HTTPS is not provided by this crate. The proxy
must authenticate TLS, forward the configured Host (including the explicitly
configured port, or omit default 443), preserve response bytes/proof headers,
reject bodies on read routes, disable shared caching, and enforce request/header/
body, connection, per-client rate, egress, and bandwidth limits. When discovery
is explicitly enabled, allow only its bounded registration POST and corresponding
OPTIONS preflight described below; do not apply a blanket body rejection to that
route. Configure the exact
browser HTTPS Origin explicitly. `CorsOrigin::loopback_development` is a separate
opt-in local development setting. Cookies, authorization headers, credentials,
CORS wildcards, and public wildcard listeners are unsupported. CORS is a browser
access policy, not peer or application authorization.

## Explicit activity publisher

`ManagedPeer::create_with_activity(config, NEW_STATE, activity_config)` opens every
explicitly listed existing activity store with its exact full room scope and
immutable limits before signing a READ|PUBLISH advertisement. It never creates a
missing store or upgrades existing READ state. Room admission still requires
independently verified current owner policy; a PUBLISH claim grants no membership,
validator authority, global ordering or private-room secrecy.

The new private `activity-mode` marker binds the sorted full room IDs, absolute
store paths, limits, network, peer key and endpoint. `open_with_activity` requires
the exact marker/configuration before store recovery. Ordinary `open` refuses it;
a missing, corrupt or torn marker is preserved and refused. Reordering the same
room configuration is harmless. Marker mutation poisons renewal until a valid
reopen; no API changes mode or reconstructs missing counters. Incomplete initial
marker/reservation creation fails closed and requires operator investigation,
not a silent reset. Existing partial-renewal recovery applies in both modes and
checks the exact expected advertisement capabilities before removing preparation.

The operator-controlled proxy must explicitly permit the bounded `/vhalla/v1/activity`
GET/POST/OPTIONS route when using this API. It carries public signed plaintext,
not private messages. Keep proxy rate/body limits and exact CORS origin guards.
Native startup/recovery and loopback HTTP fixture tests qualify this source path;
they do not constitute external TLS or public deployment qualification.

## Version 1 wire

The `vhalla_public_protocol::response` module is the portable specification:

- `GET /vhalla/v1?nonce=<64 lowercase hex>` returns the retained advertisement.
- `GET /vhalla/v1/bootstrap?nonce=<64 lowercase hex>` returns exact bootstrap bytes.
- `GET /vhalla/v1/bundles?after=<u64>&frontier=<64 lowercase hex>&count=<1..32>&bytes=<1..2097152>&nonce=<64 lowercase hex>` returns a canonical bundle page.

Parameter order and decimal/hex encodings are exact. Nonce must be nonzero;
clients generate a fresh unpredictable 32-byte nonce for every attempt. Only
HTTP/1.1 GET without a body is supported on these three READ routes; they need
no custom browser request headers and have no OPTIONS/preflight route. The
optional discovery routes have their own POST and preflight rules below.

Every successful HTTP-200 body has `X-Vhalla-Proof`, lowercase hex of the `VHPR1`
binary proof. Its domain-separated strict Ed25519 signature binds immutable
network ID, full application key, complete typed GET context including nonce,
and SHA-256 of the entire body. Clients retain the expected request and verify
against the independently selected full peer key/network. The response must be
HTTP 200; errors are deliberately untrusted and grant no authority. Fresh nonce
proof prevents reuse of a captured response for another attempt. It proves
that the named key answered, not that its route owns TLS, its history is complete,
or its observed HEAD is globally latest. TLS and route/DNS policies still apply.

A page is `VHPG` plus version byte 1, observed local HEAD height (u64 BE), HEAD
frontier (32 bytes), final returned height (u64 BE), bundle count (u8), then
repeated u32 BE length and exact opaque bundle bytes. The page contains at most
32 bundles totaling 2 MiB. `BundlePage::decode` checks framing and request bounds;
`CertifiedClient::prepare` then verifies each certificate, every canonical bundle
field, and application replay against the independently pinned bootstrap and
incremental complete frontier. A valid response proof cannot replace that step.

## Bounds and publication

The adapter permits at most 64 concurrent sockets/unfinished blocking jobs and
8 per immediate socket source IP. Active IP entries disappear when their last
permit drops. A reverse proxy's users share that proxy IP, so the proxy needs
its own per-user/IP limits. Each connection serves one request and has a 15-second
absolute lifetime; headers have a 5-second deadline, 8 KiB buffer and 32-header
ceiling. Targets are limited to 512 bytes. Blocking journal operations have a
10-second response deadline and retain admission if the filesystem remains
stuck after the socket closes. OS filesystem operations cannot be forcibly
cancelled. Shutdown stops accepting and drains replies for at most 15 seconds;
a still-running blocking disk read retains custody/admission afterward. An unavailable disk can exhaust this bounded service until recovery.

A range snapshots HEAD once, validates its indexed tip, and reads only exact
contiguous published height indexes. It never enumerates/recovers the journal,
creates directories, advances HEAD, deletes or repairs files. Unpublished bundles
and temporary pins stay invisible. Startup checks the first published predecessor
against derived genesis; it does not replay all historical certificates. All
client-side certification remains necessary. Bootstrap is held once in shared
memory and bounded by its canonical decoder; journal response working memory is
bounded per admitted request. Operator-controlled file ancestors, immutable
published history, disk quotas, archive retention, and free-space monitoring
remain deployment requirements.

## Managed publication, recovery, and CLI activation

`ManagedPeer::create(config, state_dir)` explicitly creates a new private
publisher directory; `ManagedPeer::open` requires an existing one. The configured
advertisement path is exactly `STATE/advertisement`. Both validate the independently
pinned bootstrap, derived genesis and existing custody key before publishing.
Neither creates an identity or mutates the application journal. `bind().run()`
retains the custody owner, serves the read API, and checks renewal once per minute.
Advertisements last 24 hours and renew with 12 hours remaining. No sequence is
derived from a timestamp. An expired but correctly signed retained descriptor can
be reopened and renewed from its durable sequence evidence.

The experimental CLI activation is:

```text
vhalla public serve BOOTSTRAP PIN64 KEY_DIR JOURNAL PEER_STATE HTTPS_ENDPOINT ALLOWED_ORIGIN --new-state
```

Use `--new-state` only for a genuinely new publisher state and retain that state
for the lifetime of this network/full application key. Omit it on every restart.
Existing state is never overwritten. `--listen LOOPBACK_IP:PORT` overrides the
loopback default; public/wildcard addresses are rejected. `--dev-origin` explicitly
permits a positional `http://LOOPBACK_IP:PORT` origin during local development.
SIGINT/SIGTERM stop accepting and drain bounded in-flight responses. None of these
commands configures TLS, DNS, a firewall, a public listener, or a hosting provider.

The private 0700 state directory contains a 0600 lock, scoped `sequence` reservation,
and signed `advertisement`. A reservation binds full network/key/route, sequence,
last issuance and a corruption-detection hash. It is written to `sequence.tmp`,
file-synced, renamed and directory-synced BEFORE signing. The signed advertisement
is separately file-synced, atomically renamed and directory-synced before managed
readers install its bytes in their serving cache. Managed discovery never reads
an unsynced replacement merely because its filename has become visible.

Any uncertain publication poisons that writer and closes managed discovery until
reopen; the renewal loop stops the listener. Reopen validates the canonical scoped
reservation and any complete temporary reservation, retains the highest floor,
and validates every existing signed descriptor against that floor. It normalizes
only validated temporary artifacts, then reserves a strictly higher sequence and
publishes fresh evidence. An incomplete `sequence.tmp` is discarded only when its
available bytes match the next reservation under the intact committed scope.
An incomplete `advertisement.tmp` must match the durable reservation and route;
that reserved sequence is skipped. No signature can precede reservation
publication. Clock, scope and existing signed evidence checks precede cleanup.
A valid old advertisement remains intact until its replacement is published.
Tests cover creation, partial writes, syncs and renames, plus every truncated
reservation and advertisement prefix.

Corrupt/truncated authoritative files, malformed complete temporary files, foreign
scope, advertisements above the reservation,
conflicting same-sequence evidence, unknown files, missing all reservation evidence,
sequence exhaustion and clock rollback fail closed while preserving evidence.
Recovery never reconstructs a lost counter from a descriptor. Operator-controlled
ancestors, retained publisher state and backups remain required; this is not
hostile-disk rollback protection and cannot discover an operator's independently
created state directory elsewhere. Never use a fresh state directory to reset a
previously advertised network/key's sequence.

The lower-level `Peer::open` remains available for an independently operated static
advertisement publisher. It reloads a bounded signed file and accepts identical
bytes or a verified higher sequence, but requires explicit renewal. Native custody
prevents a separate CLI from reopening the same key while the service holds it;
`ManagedPeer` solves this by owning signing and publication within that process.
`Peer::sign_advertisement` remains a constrained typed hook, not a generic signing
oracle or durable publication receipt.

These APIs do not establish complete public-network readiness. Activity PUBLISH
activation, automatic discovery traversal, browser DNS enforcement, NAT traversal, long-term history operations, TLS deployment, and adversarial
multi-peer production qualification remain separate work. Discovery admission
limits described below bound local resource use; they do not establish independent
operators or Sybil resistance. Local adapter tests do not qualify a public deployment.

## Optional public route discovery

`Peer::enable_discovery(DiscoveryConfig { directory, create_new })` (also
forwarded by `ManagedPeer`) explicitly activates a separate private discovery
registry. `create_new: true` requires a fresh directory; normal restart uses
`false`. This adds only route metadata registration, never validator admission,
room rights, journal writes, native dialing or DNS resolution. The local typed
`Peer::discovery_exchange` API and the HTTP endpoints use the same admission
path. Native publishers can sign the checked work response with
`Identity::sign_peer_registration`; no raw key export is involved.

The maintained operator entry point is `vhalla public discovery-serve`, built
with the `experimental-public` CLI feature. It can run without outgoing seeds or
register to up to four explicitly selected, independently pinned seed routes.
The CLI resolves each explicitly selected DNS seed in a bounded supervised child,
rejects mixed/non-public answer sets and pins the checked addresses while preserving
TLS hostname validation. This does not change browser Fetch or authorize automatic
candidate dialing.
See the [CLI runbook](../vhalla-cli/README.md#public-discovery-peer) for fresh-state
and restart commands, bounded work, and the `/usr/bin/curl` system TLS dependency.
The selected seed files supply restart sequence floors; newer floors observed
during this command are retained only in memory. No discovered route is dialed
automatically. The local advertisements remain READ-only.

The three canonical routes are `GET /vhalla/v1/peers`,
`GET /vhalla/v1/peers/challenge`, and `POST /vhalla/v1/peers/register` with the
exact query encodings defined by `DiscoveryRequest`. Listings contain at most
16 independently signed advertisements in complete-public-key order. Continue
with the returned generation and full key; a generation conflict means restart
the listing. Every successful body has a fresh nonce-bound discovery proof in
`x-vhalla-proof`. Verify both that proof and every subject advertisement against
the independently pinned network. A listed hostname is not reachability,
operator independence, or authority. Browser Fetch cannot pin a DNS resolution;
this interface does not authorize automatically dialing arbitrary DNS candidates.

Registration requires `application/octet-stream` and either one canonical
Content-Length or HTTP/1.1 chunked framing. The decoded body is capped at
1,861 bytes (`MAX_REGISTRATION_BYTES` in the current portable protocol), including
on chunked input, and must finish within five seconds. Empty bodies, trailers, conflicting framing,
content encodings, credentials, and bodies on discovery GETs are rejected.
OPTIONS accepts only the exact configured Origin, the route's GET/POST method,
and an optional `content-type` request-header declaration. Discovery still shares
the socket, header, absolute connection, and blocking-operation bounds above.

New publisher keys must solve the existing Botcaptcha Hashcash contract at a
fixed 20-bit difficulty (about `2^20` SHA-256 attempts in expectation). Retained
keys use one bit for renewal. The receiver-signed 60-second challenge commits
full network, receiver key, publisher key, exact signed-advertisement hash and
request nonce. A changed advertisement cannot reuse its work. Solvers require
an explicit attempt budget, capped at `2^24` per call; `solve_range` permits
cancellation between bounded chunks. Expired challenges and cheap work presented
after a key's retirement are refused. This is hardware-biased and outsourceable
admission cost, not proof of personhood or a Sybil-resistance guarantee.

The registry retains at most 512 active descriptors and cooling replay floors
combined. Expired routes disappear from listings immediately. Their floors stay
until `accepted_at + 300 seconds + 24 hours`, covering the maximum permitted
issuer skew and every formerly acceptable advertisement lifetime. Retirement
atomically removes the entry and advances a durable issuance cutoff to at least
`accepted_at + 300 seconds`; absent keys must present advertisements issued
strictly after that cutoff. Clock rollback fails closed. This is a finite-horizon
registry contract, not lifetime sequence memory. Clients retain their own peer
sequence floors independently.

A full registry refuses new keys while retained publishers may update. An
attacker maintaining 512 admissible identities can deny new slots; Hashcash and
quotas do not eliminate that limit. A fixed 240 requests/minute global limit and
60 requests/minute per immediate socket IP bound discovery activity, with at
most 256 source-IP rate entries. A TLS reverse proxy appears as one source IP;
operators must budget and enforce appropriate external edge limits. No forwarded
header is accepted as an authenticated client IP.

Registry state is one bounded, checksummed canonical snapshot under private
custody and a lifetime writer lock. Updates fsync the temporary snapshot before
rename and directory sync; memory becomes visible only after that completes.
An uncertain publication poisons the current owner. Reopen validates and
reconciles complete retained pending evidence. With a valid stable registry,
structurally incomplete canonical temporary bytes can be discarded only after
scope, available monotone fields, complete signed entries, retained replay floors
and clock checks pass. A validated stable file and its directory are re-synced
before restart succeeds, including a same-clock retry after an uncertain rename.
This preserves the stable registry and requires retrying
the interrupted registration; it does not acknowledge the incomplete candidate.
Malformed complete snapshots, foreign prefixes, clock rollback and incomplete
initial creation without a valid stable registry remain preserved and fail closed.
Exact retained-ad retries return the prior admission
without extending its timestamp, floor, or receipt generation. The existing
snapshot remains until the replacement is fully written and fsynced; successful
publication additionally requires rename and directory sync. This does not
defend against an owner rolling back the entire state directory from backup.
