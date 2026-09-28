# Host private rooms with iroh

In development. Build this checkout with `experimental-private` to use iroh
for private rooms. The commands here describe this source version; check an
installed release's help before using them.

An iroh host has a saved public endpoint identity. Members connect to that
identity and authenticate with their own mailbox tokens. Iroh attempts direct
connectivity and can carry the encrypted connection through the configured
relay when a direct path is unavailable. You do not need a public IP address,
certificate authority, certificate renewal or a Tailcat process.

The host stores opaque room ciphertext while members are offline. It must be
running to send or fetch messages. MLS encrypts the room contents separately
from iroh's transport encryption. The network relay can observe connection
metadata and traffic volume, including endpoint identities and the opaque
mailbox namespace in protocol negotiation, but does not receive the room keys
or mailbox token in plaintext. The default public relay is a third-party service whose
availability you do not control.

## Start a host

Build the CLI and create a fresh host directory under an existing parent:

```sh
cargo build --locked -p vhalla-cli --features experimental-private
./target/debug/vhalla private-host init /absolute/private/host
./target/debug/vhalla private-host serve /absolute/private/host
```

The directory is owner-private. `endpoint.key` stores the host's private
identity; `connection.json` contains its public endpoint and mailbox namespace.
Each `client-N.token` is a separate bearer credential. Keep the whole host
directory across restarts, and share only a participant's invitation or selected
public connection information and their own token. Never share `endpoint.key`.

Inspect the host from another terminal:

```sh
./target/debug/vhalla private-host status /absolute/private/host --probe
```

The probe makes an authenticated mailbox request. Stop the foreground host with
Ctrl-C. The `install` and `uninstall` commands manage its per-user service on
macOS or Linux as described in [local host lifecycle](local-host.md#foreground-and-login-lifecycle).
Choose a stable executable with `init --executable /absolute/path/to/vhalla`
before installing that service.

## Invite a member

Use `private invite` with the host directory and an enrolled credential index.
The resulting confidential file contains the room offer, pinned iroh endpoint,
mailbox namespace and that participant's token. `private join --invite` creates
the member's room and delivery profile. The [private-room commands](private-rooms.md)
describe the required account, validity and operation arguments.

Iroh invitations use version two. A recipient does not choose an IP address or
copy a CA certificate. Reject an invitation if its endpoint identity is not the
one you selected through your trusted invitation channel. Network reachability
does not establish room membership.

`add-credential`, `revoke-credential` and `replace-credential` apply to iroh
hosts. Drain and restart the host to activate credential changes. Replacing a
token preserves its credential identity and storage quota; it does not create
new capacity or redirect queued messages.

## Configure agent delivery

Joining through an iroh invitation writes the transport selection for you.
For a manually created profile, use version four with this transport object:

```json
{
  "kind": "iroh",
  "endpoint": {
    "endpoint_id": "64 lowercase hex digits from connection.json",
    "relay_url": "https://use1-1.relay.n0.iroh.link.",
    "addresses": []
  }
}
```

Place it under `transport` in the delivery JSON, alongside `context`,
`namespace`, `token`, `state`, retry limits and delivery budgets. Omit the TLS
fields `addr`, `tls_name` and `ca`. The rest of the [agent delivery
configuration](cli-agents.md#local-hosting-and-persistent-delivery) applies.
The persistent queue binds the endpoint key and namespace. Changing a routing
hint keeps that identity; selecting another key or mailbox refuses the old
queue.

A browser still uses its native loopback gateway and keeps its existing origin
and storage. Gateway format three selects an iroh upstream with
`{"transport":"iroh","endpoint":{...},"token_file":"/absolute/private/token"}`.
The browser capability remains separate from the host's mailbox token.

## Select a network path

The default uses iroh's North America east relay. Choose another HTTPS iroh
relay with `init --relay-url https://your-relay.example`. The relay URL is part
of the selected route and is never taken from a mailbox response. No public
endpoint discovery service is enabled.

For a local test or a directly reachable host, disable relay traffic and bind
a fixed address:

```sh
./target/debug/vhalla private-host init /absolute/private/local-host \
  --iroh-bind 127.0.0.1:9474 --relay-url none
```

Loopback addresses reach only this machine. Direct connections use UDP. A
relay-free host behind NAT needs a reachable UDP path supplied by its operator.
The default relay configuration permits an ephemeral wildcard bind because
members can reach the saved endpoint identity through its selected relay.

## Limits

The mailbox retains the existing per-credential storage and request limits.
Iroh does not replace the mailbox's durable storage, room membership checks,
exact ciphertext retries or signed recipient acceptance. Endpoint keys are
transport identities and do not confer room authority.

Certificate renewal, Tailcat templates and mailbox generation-transition tools
apply to explicitly selected TLS hosts. Iroh hosts refuse those operations.
Choose `init --transport tls` when those tools are required; see the [TLS host
guide](local-host.md). There is no automatic conversion of saved TLS host or
delivery state.

Local direct, relay and independent-machine results are separate claims. The
[implementation plan](iroh-transport-plan.md) records the validation scope;
historical TLS measurements do not establish iroh behavior across devices.
