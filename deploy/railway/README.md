# Private-room host on Railway

This directory deploys a Valhalla private-room relay host on Railway: a small
container builds `vhalla` from this repository, runs the relay's unchanged
loopback listener behind a TCP bridge, and keeps the host home on a mounted
volume. Members reach it over Railway's public TCP endpoint with the same
pinned TLS check every other route uses.

The shape was tested end to end on Railway's smallest tier: members joined
and exchanged messages over real public egress, redeploys preserved the host
home, and the running service measured about 17 MB resident — inside the
$1/month included usage on Railway's free plan, so it costs nothing to run.
See [docs/local-host.md](../../docs/local-host.md#a-hosted-container) for the
mechanics and the two operational findings (keep container stops graceful).

## One-click deploy

<!-- TEMPLATE_URL -->

## Deploy by hand

1. New project → deploy this repository with `railway.toml` (it points the
   build at `deploy/railway/Dockerfile`; the source build takes a while).
2. Add a volume mounted at `/data` (up to the free plan's 500 MB is plenty;
   the host home uses megabytes).
3. Create a TCP proxy on the service's public networking page targeting port
   `19473`, or set `APP_PORT` to whichever internal port you map.
4. Deploy. The first boot runs `private-host init` once on the volume; later
   boots serve the same home.
5. Extract client material once via `railway ssh` (keep the modes intact):
   `ca.der`, `client-1.token`/`client-2.token`, and the namespace from
   `config.json` or `private-host status`.

Clients then dial the proxy's `name:port` — `--addr` and delivery profiles
accept DNS names resolved per use, while TLS still verifies the pinned CA,
the chosen `--tls-name` and the opaque namespace.

## Cost

Measured on the tested deployment: `vhalla` 13 MB + the socat bridge ~4 MB
resident, near-zero idle CPU — roughly $0.40/month of metered usage against
Railway's per-second rates, within the free plan's $1 monthly included usage.

## Files

- `Dockerfile` — source build of `vhalla` (bookworm toolchain stage, slim
  runtime with `socat`). When a release publishes the `*-linux-musl`
  artifact, this file can switch to fetching the verified tarball instead.
- `start.sh` — init-once, bridge, serve.
- `railway.toml` — points Railway builds at the Dockerfile.
