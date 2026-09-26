# Changelog

Each section is the release notes for one tag. The release workflow copies the
section whose heading matches the tag onto the GitHub Release page and refuses
to publish when that section is missing or empty. Write the section in the
change that prepares the tag, and keep published sections as they shipped.

## 0.2.7 - 2026-09-26

`vhalla` now explains itself in plain words. Help is grouped by task, a bare
`vhalla` prints a short overview, and errors name the cause and one next
command. Before a private host listens beyond this computer, macOS network
permissions are explained first. Rooms nodes can also dial peers by name or
IPv6 address. Tag v0.2.6 was not published, so this section covers every
change since v0.2.5.

- `vhalla` with no arguments prints a short overview. `vhalla --help` is
  grouped by task and lists only the commands this build has; `vhalla help
  <topic>` and `vhalla <command> --help` print one topic, and `vhalla help all`
  prints the complete command reference. An unknown command suggests the
  closest one and exits 2.
- Errors at a terminal read as one sentence and one next command. Identity,
  private room, private host, gateway and paired-chat errors no longer print
  Rust debug output. Scripts and agents keep the exact `vhalla: ...` line.
  `NO_COLOR`, `TERM=dumb` and non-UTF-8 locales get ASCII symbols.
- A listener that can't start names the cause: another program on the port
  (with the `lsof` command that finds it), a port that needs extra rights, or
  the system error.
- `vhalla identity backup` warns before printing the recovery phrase that
  anyone with it can sign as you. Its output is unchanged.
- When the macOS firewall is on, `private-host serve` explains the incoming
  connections notice before listening beyond this computer (Enter continues,
  `s` skips and prints the firewall settings link). When a relay on your local
  network is up but can't be reached, the error says Local Network access may
  be off for your terminal app and links to that setting.
- Rooms nodes dial persistent peers given as DNS names (`/dns4`) or IPv6
  literals (`/ip6`), which previously stopped the node at startup.
- `deploy/rooms-seed` runs a rooms seed validator on Railway-class hosts, and
  each Railway service now builds its own Dockerfile.

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
