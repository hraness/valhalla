# Rooms seed validator

Runs `vhalla rooms node` — one Malachite rooms-consensus validator — on a
platform with Docker builds, a public TCP endpoint and a mounted volume
(Railway is the tested shape). The validator's libp2p listener binds the
wildcard address inside the container and the provider's TCP proxy
fronts it, so peers dial the public `host:port` the platform assigns.

## Shape

- `Dockerfile` builds `vhalla` with `experimental-rooms-node` from this
  repository.
- `start.sh` scaffolds `NODE_HOME` once from environment — the journal
  and WAL then live on the volume and survive redeploys — then execs
  `vhalla rooms node`.
- One service per validator. A seed mesh is a small set of these
  services plus their `KEY@host:port` peer lines.

## Environment

| Variable            | Meaning                                              |
| ------------------- | ---------------------------------------------------- |
| `NETWORK_FILE_B64`  | base64 of the shared params file `rooms network-init` wrote (identical on every validator) |
| `NODE_KEY`          | this validator's 64-hex private seed; its public key must appear in `--validators` |
| `NODE_PORT`         | libp2p listen port the TCP proxy targets (default `9473`) |
| `PEERS`             | comma-separated `KEY@host:port` entries for the other validators |
| `LISTEN`            | bind address (default `0.0.0.0`)                     |
| `DISCOVERY`         | `true` lets joining observers bootstrap through this validator (default `true`) |

## Railway steps

1. New project → one service per validator, built from
   `deploy/rooms-seed/Dockerfile` (point `railway.toml` or the service's
   dockerfile path at it).
2. Attach a volume mounted at `/data` to each service.
3. `railway tcp-proxy create --port 9473 --service NAME` on each and
   record the public `host:port`.
4. Generate validator seeds locally, run `rooms network-init` for the
   shared params file, then set each service's `NODE_KEY`, `PEERS`
   (the other validators' public endpoints) and `NETWORK_FILE_B64`.
5. Deploy; `rooms status`/`node-check` against any scaffolded home
   confirms the mesh, and the service logs print the committed height.

## Notes

- Persistent peers are pinned (`KEY@`) on purpose: the seed mesh knows
  every validator, while `DISCOVERY=true` lets a new observer join by
  dialling any single member.
- `NODE_KEY` is the validator's signing seed — keep it a platform
  secret; `NETWORK_FILE_B64` is public material by design.
- A validator that sleeps stalls quorum. Size the set for the
  availability you actually operate, and rotate members in through
  `rooms rotate` rather than re-editing files.
