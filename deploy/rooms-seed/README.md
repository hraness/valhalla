# Rooms seed validator

Runs `vhalla rooms node` — one Malachite rooms-consensus validator — on a
platform with Docker builds, a public TCP endpoint and a mounted volume
(Railway is the tested shape). The validator's libp2p listener binds the
wildcard address inside the container and the provider's TCP proxy
fronts it, so peers dial the public `host:port` the platform assigns.

The [27 September 2026 mesh report](../../docs/rooms-seed-mesh-2026-09-27.md)
records a three-seed deployment, discovery from one bootstrap peer, a laptop
joining and leaving the voting set, and matching committed state.

## Shape

- `Dockerfile` builds `vhalla` with `experimental-rooms-node` from this
  repository.
- `start.sh` scaffolds `NODE_HOME` and the genesis social store once
  from environment — the journal, WAL and committed social snapshot
  then live on the volume and survive redeploys — then execs
  `vhalla rooms node SOCIAL_HOME NODE_HOME REALM --config node.json`.
- One service per validator. A seed mesh is a small set of these
  services plus their `KEY@host:port` peer lines.

## Environment

| Variable            | Meaning                                              |
| ------------------- | ---------------------------------------------------- |
| `NETWORK_FILE_B64`  | base64 of the shared params file `rooms network-init` wrote (identical on every validator) |
| `REALM`             | the 32-hex `realm` id from the shared params file |
| `NODE_KEY`          | this validator's 64-hex private seed; its public key must appear in `--validators` |
| `NODE_PORT`         | libp2p listen port the TCP proxy targets (default `9473`) |
| `SOCIAL_HOME`       | genesis social store path (default `/data/social`) |
| `PEERS`             | comma-separated `KEY@host:port` entries for the other validators |
| `LISTEN`            | bind address (default `0.0.0.0`)                     |
| `DISCOVERY`         | `true` lets joining observers bootstrap through this validator (default `true`) |
| `ADVERTISE`         | public TCP proxy `HOST:PORT` (comma-separated for multiple endpoints); replaces private listener addresses in signed discovery records |

## Railway steps

1. New project → one service per validator, built from
   `deploy/rooms-seed/Dockerfile` (point `railway.toml` or the service's
   dockerfile path at it).
2. Attach a volume mounted at `/data` to each service.
3. `railway tcp-proxy create --port 9473 --service NAME` on each and
   record the public `host:port`. Set each service's `ADVERTISE` to its own
   public endpoint so joining peers can dial the addresses discovery shares.
4. Generate validator seeds locally, run `rooms network-init` for the
   shared params file, then set each service's `NODE_KEY`, `REALM`,
   `PEERS` (the other validators' public endpoints) and
   `NETWORK_FILE_B64`.
5. Deploy and run `node-check` to verify the local configuration and
   genesis store. Submit a batch and verify its commit in every validator's
   journal to confirm live consensus. To inspect that history through
   `rooms status`, use a CLI built with `experimental-rooms-replica` and a local
   read replica; the seed image includes only `experimental-rooms-node`.
   A local status check alone cannot establish peer connectivity or quorum
   availability.

## Notes

- Persistent peers are pinned (`KEY@`) on purpose: the seed mesh knows
  every validator, while `DISCOVERY=true` lets a new observer join by
  dialling any single member.
- `NODE_KEY` is the validator's signing seed — keep it a platform
  secret; `NETWORK_FILE_B64` is public material by design.
- First setup can resume after the genesis social store is created but
  before `node.json` is published. The script uses `--resume-social` with
  the supplied `NODE_KEY`, verifies an empty genesis store, and refuses
  any application state, WAL, pending intake, or unknown node files.
  Missing artifacts after a node has run require restoring the saved
  config or store. Startup preserves retained files and reports failures.
- `ADVERTISE` is validated and saved during first setup. On later starts it
  overrides the advertised endpoints without changing the persisted node
  config, identity or consensus history. Leave it unset to use the saved
  configuration. Discovery behind a TCP proxy requires a public endpoint.
- A validator that sleeps stalls quorum. Size the set for the
  availability you actually operate, and rotate members in through
  `rooms rotate` rather than re-editing files.
