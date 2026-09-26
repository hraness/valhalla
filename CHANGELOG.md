# Changelog

Each section is the release notes for one tag. The release workflow copies the
section whose heading matches the tag onto the GitHub Release page and refuses
to publish when that section is missing or empty. Write the section in the
change that prepares the tag, and keep published sections as they shipped.

## 0.2.5 - 2026-09-26

Rooms consensus can replace its validator set from inside the protocol, and
rooms nodes can find peers beyond the ones they were configured with. A
private host can now run on a LAN, a public address or a hosted container,
and the release adds static Linux builds. Tag v0.2.4 was not published, so
this section covers every change since v0.2.3.

- `vhalla rooms rotate` schedules a complete replacement validator set at a
  future height, and `vhalla rooms score` derives that set from the committed
  social-credit ledger. A rotation must activate more than two heights after
  the current frontier, so the old set still checks the batch that carries it.
- `vhalla rooms node-init --discovery true` turns on libp2p peer discovery,
  using the configured peers as bootstrap nodes. It needs at least one peer and
  cannot be combined with a closed peer list.
- `private-host` can listen on a LAN or public address and publish a separate
  `--advertise` address, and clients accept a DNS `name:port` relay endpoint.
- `vhalla private invite` writes one invite file that carries both the room
  offer and the relay credential.
- A recipient can join a private room through the relay instead of moving a
  response file by hand. A drained room can move to a new mailbox generation,
  and an owner can review devices, remove one, or hand ownership to another
  live device on the same account.
- The host holds a quiet client's page request open until a new mailbox item
  arrives. On Linux, the host, the gateway and the Tailcat overlay can run as
  per-user systemd units.
- The release adds static `vhalla` archives for x86-64 and ARM64 Linux
  (`x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`), which do not
  depend on the system glibc version.
- A Railway template and deploy recipe run a private host in a hosted
  container.

## 0.2.3 - 2026-09-23

Private rooms work end to end across a local host, CLI agents and the browser:
delivery survives relay outages and restarts, and each side keeps durable
evidence of what was sent and accepted. The release also adds `vhalla demo`,
`vhalla --version` and a Homebrew tap.

- Delivery jobs stay live through a relay outage and resume when an operator
  re-arms them; an outage no longer counts as a definitive refusal.
- `private-host` gains `add-credential`, `rotate` and `renew`, and
  `private-host status --probe` and `private-gateway status --probe` check the
  running service. The host and gateway are supervised with a bounded event
  log, and gateway admission refusals return explicit statuses.
- `vhalla private agent-launch` starts an agent under an operator-reviewed
  policy, and `vhalla private delivery-status` reports delivery progress
  without writing to the room.
- The browser client delivers private messages through a durable, bounded
  engine and records each accepted message.
- Refusals from the private-room kernel name their cause (stale or future
  epoch, control or ratchet gap, clock regression) instead of failing
  generically.
- `vhalla demo` runs a narrated eight-step tour on the local machine without
  touching the network, and `vhalla --version` reports the compiled feature
  set.
- `brew install hraness/tap/vhalla` installs the CLI from the Hraness Homebrew
  tap.
