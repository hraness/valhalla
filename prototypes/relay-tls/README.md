# Relay TLS qualification

This isolated experiment runs real TLS 1.3 over numeric loopback sockets around
Valhalla's production `RelayItem`, `Store`, `FileStore` and mailbox semantics.
All adapter code is test-only. The production workspace does not depend on this
crate, and this experiment adds no production TLS feature, listener, deployment,
public endpoint or account credential.

The client uses an explicit synthetic CA and exact server name. It completes
certificate and name verification before constructing or sending a token-bearing
request. There is no ambient trust-store lookup, DNS resolution, permissive
verifier, early data or plaintext fallback. Test credentials exist only in memory.
One absolute deadline covers connection, handshake, partial TLS records and the
application request/response. Accepted server connections are served sequentially
with a fixed deadline; this qualifies a bound, not fair or concurrent service.

The adapter mirrors the existing native PUT/PAGE frame bytes. A regression
captures requests from the production `SocketRelay` and compares them byte for
byte with decrypted TLS requests; parsed pages are also compared, including
canonical empty absence beyond the mailbox head. Promotion must share a reviewed
codec rather than maintain duplicate transport parsers.

## Run

Use Rust 1.98 or newer and a matching compiler/Clippy driver. From the repository
root:

```sh
cargo test --locked --manifest-path prototypes/relay-tls/Cargo.toml
cargo clippy --locked --manifest-path prototypes/relay-tls/Cargo.toml --all-targets -- -D warnings
```

On Hraness hosts, run each command through the installed absolute `host-run`
with `--mode=shared --lane=compute`. Select the complete Rust toolchain in that
child's `PATH`, plus explicit matching `RUSTC` and `RUSTDOC`, if a Homebrew compiler
otherwise takes precedence. `--offline` is supported after the standalone lock's
packages are cached. This crate has its own `Cargo.lock` and ignored `target/`;
it does not modify the production lockfile.

## Evidence and contract

Local qualification on 2026-09-22 with Rust1.98.1/macOS passed all nine real-socket
tests and strict all-target Clippy (`-D warnings`). These are synthetic loopback
results; no public service or independent-machine delivery was exercised.

The qualification exercises:

- A real verified TLS handshake, exact idempotent retention and bounded paging.
- Wrong CA and wrong server name, with zero decrypted application bytes received
  and no mailbox mutation.
- Wrong token, foreign namespace and full quota, with no new retained item.
- Malformed and oversized frames followed by a successful verified client.
- An unauthenticated trickling handshake that times out before the next client
  succeeds.
- A lost receipt followed by a real `FileStore` close/reopen and an exact retry
  returning the original position and commitment.
- Production frame/page parity, including empty absence beyond the retained head.
- Maximum-sized retained items spanning the 4 MiB wire-page budget and resuming
  through the returned cursor.

Successful receipts mean relay retention only. The experiment never creates a
member acknowledgment or claims recipient acceptance, human reading, fresh room
membership, honest relay behavior or end-to-end delivery. Lost-receipt recovery
reuses the original canonical ciphertext; it never requests another encryption.
Test-only traces retain synthetic frames in memory for parity checks; this is
not an operational logging design.

## Promotion boundary

Still separate work: real server credential provisioning and rotation; mailbox
credential scope, replacement and zeroization; bounded concurrent admission,
per-client fairness and abuse controls; operator resource configuration; offline
retry scheduling; and independent-machine interruption/latency qualification.
The test adapter's empty-beyond-head read is an absence result, not permission to
roll back a durable catch-up cursor. Production `ScanDirectory` enforces that
separate monotonicity contract.

A later offline controller can persist one exact encoded item, its commitment and
a bounded retry schedule, reconciling an uncertain outcome only by exact retry.
It must maintain separate pending, retained and independently authenticated
member-accepted states. That controller and encrypted member acceptance receipts
are not implemented by this TLS experiment. No public activation is authorized
or performed by these tests.
