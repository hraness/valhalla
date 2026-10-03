# Private-room host on Railway

This directory deploys a Valhalla private-room relay host on Railway: a small
container builds `vhalla` from this repository, selects `--transport tls`, runs a
loopback listener behind a TCP bridge, and keeps the host home on a mounted
volume. Members reach it over Railway's public TCP endpoint with the same
pinned TLS check.

This recipe uses the provider's TCP proxy. The source CLI defaults to iroh for
new private hosts, but this recipe deliberately selects TLS and does not
exercise an iroh deployment. For a host using endpoint identities and relay
fallback, follow the [iroh host guide](../../docs/iroh-private-rooms.md).

The shape was tested end to end on Railway's smallest tier: members joined
and exchanged messages over real public egress, redeploys preserved the host
home, and the running service measured about 17 MB resident. This is a
historical qualification snapshot from 2026-09-26; Railway plan names, credits,
and prices change, so it is not a current cost or availability promise.
See [docs/local-host.md](../../docs/local-host.md#a-hosted-container) for the
mechanics and the two operational findings (keep container stops graceful).

## One-click deploy

[![Deploy on Railway](https://railway.com/button.svg)](https://railway.com/new/template/valhalla-private-host?utm_medium=integration&utm_source=button&utm_campaign=valhalla-private-host)

The published template wires steps 1–3 below for you: it deploys this
repository's Dockerfile, attaches a `/data` volume and creates a TCP proxy on
port `19473`. The `APP_PORT` and `HOME_DIR` variables stay empty for the
defaults. Continue at step 4 for first boot and client material.

## Deploy by hand

1. New project → deploy this repository. The root `railway.toml` points the
   build at `deploy/railway/Dockerfile`; the source build takes a while.
2. Add a volume mounted at `/data` (up to the free plan's 500 MB is plenty;
   the host home uses megabytes).
3. Create a TCP proxy on the service's public networking page targeting port
   `19473`, or set `APP_PORT` to whichever internal port you map.
4. Deploy. The first boot runs `private-host init --transport tls` once on the volume; later
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
the rates observed in that historical snapshot. Check the current Railway plan
and set an explicit budget before running unattended experiments; this recipe
does not authorize an upgrade or imply free hosting.

## Files

- `Dockerfile` — source build of `vhalla` (bookworm toolchain stage, slim
  runtime with `socat`). When a release publishes the `*-linux-musl`
  artifact, this file can switch to fetching the verified tarball instead.
- `start.sh` — init-once, bridge, serve.
- `railway.toml` at the repository root — points Railway builds at the
  Dockerfile with the repository as build context.
