Iroh reduces the work of connecting a private-room client to a host behind a router. The client names the host by its public key; iroh establishes an authenticated connection, tries a direct network path, and can carry the connection through a relay. Valhalla uses that transport for new private hosts so an owner can start one without distributing a certificate authority or configuring a separate tunnel.

**In development.** The implementation described here is in the [merged source](https://github.com/hraness/valhalla/commit/28a4f60dfa1c38265027abfadaba1284244d47a8). Use the [private-room source setup](/docs/private-rooms/) to try it. This article does not assume that an installed release includes it.

## Private P2P needs a reachable machine

A connection that works between two processes on a laptop can fail when one moves to another home. A router performing network address translation, or NAT, gives several devices a shared public address and tracks their outgoing connections. An unsolicited incoming packet may have no permitted route to the device that should receive it. Knowing the device's public key does not tell packets how to reach it.

Hole punching coordinates outgoing traffic from both peers so their routers may allow a direct path. It depends on the network. A relay provides another route when the peers can reach that relay but cannot reach each other directly. Both [iroh's connection documentation](https://docs.rs/iroh/1.2.0/iroh/#connection-establishment) and [libp2p's direct connection upgrade protocol](https://github.com/libp2p/specs/blob/master/relay/DCUtR.md) describe this combination.

Private messaging also has an availability problem: a recipient may be asleep or offline. Valhalla's owner-run mailbox stores encrypted messages until members fetch them. Someone must keep that mailbox running. A network relay only forwards traffic between connected endpoints; it does not take over the mailbox's job when the owner's machine shuts down.

That gives two different meanings of “relay.” The **iroh relay** helps packets reach the host. The **Valhalla mailbox**, called a relay in some commands, stores room ciphertext. Keeping those roles separate makes the operating costs and privacy limits easier to understand.

## Iroh combines endpoint identity with connection management

[Iroh](https://docs.rs/iroh/1.2.0/iroh/) is a networking library built around QUIC connections between endpoints identified by public keys. QUIC provides encrypted, flow-controlled streams over UDP; [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000.txt) specifies its transport behavior. Iroh adds peer addressing, NAT traversal, and relay connectivity around it.

The endpoint key answers “which peer am I connecting to?” A relay URL or direct address supplies a route. During the encrypted handshake, the connecting endpoint checks that it reached the expected key. An address change can therefore be handled without redefining the peer's identity.

Connections do not have to wait for every direct attempt to fail before using a relay. Iroh describes establishing a connection through a peer's home relay, attempting hole punching, and moving to a direct connection when one succeeds. A known reachable address can also allow a direct connection from the start. If a direct route cannot be established, traffic can continue through the relay.

Iroh's transport uses TLS as part of QUIC. Valhalla's “iroh versus TLS” configuration names distinguish iroh from its separate TCP/TLS adapter; they do not mean that iroh removes TLS cryptography. What disappears from the iroh host setup is the operator's certificate-authority distribution and renewal workflow. Endpoint private keys still need protection and persistence.

## The alternatives move work to different places

These are architectural choices, not a comparative benchmark. The question for Valhalla is which choice removes setup work while fitting an owner-run mailbox and native clients.

| Approach | When it fits | Work the application or operator keeps |
| --- | --- | --- |
| Direct TCP with TLS | A host already has a reachable address, such as a server behind a TCP proxy. | Address configuration, certificate trust, and a route through firewalls or NAT. |
| QUIC without a peer-connectivity layer | The application controls reachable endpoints and needs QUIC streams. | Peer addressing, identity policy, NAT traversal, and any relay service. |
| WebRTC data channels | Browser-to-browser communication is central to the product. | Signaling, application authentication, and STUN/TURN infrastructure or a provider. |
| libp2p | A network needs a collection of peer protocols and configurable transports. | Selecting and operating those protocols, including relay and connection-upgrade behavior. |
| WireGuard or a managed mesh VPN | Members already share a private network, or need several applications to use it. | Device enrollment, network access policy, and the VPN lifecycle alongside the application. |
| Iroh | A native application needs authenticated connections to named peers across changing networks. | Trusted key exchange, application permissions, relay availability, and its own storage protocol. |

### Direct TLS and custom QUIC

Valhalla's [TCP/TLS host](https://github.com/hraness/valhalla/blob/28a4f60dfa1c38265027abfadaba1284244d47a8/docs/local-host.md) is useful when a reachable TCP endpoint is already available. Its deployment on Railway uses that route. Adding a P2P layer there is an operating decision, not a prerequisite for encrypted rooms.

Using QUIC directly would provide its stream transport, but a QUIC connection alone does not give Valhalla a peer-address distribution service or a relayed route to an unreachable host. Those pieces would need implementation and operation around the transport. Iroh supplies them behind an endpoint API, so Valhalla does not implement its own NAT traversal and relay routing. The owner has fewer setup tasks, while the application adds dependencies and relies on the selected relay's availability.

### WebRTC and libp2p

[WebRTC's peer-connection guide](https://webrtc.org/getting-started/peer-connections) explains how peers exchange session descriptions and candidate addresses over a separate signaling channel. ICE, or Interactive Connectivity Establishment, tries candidate paths. STUN helps discover network addressing; TURN can relay traffic. The application must provide the signaling channel and decide whom to trust.

WebRTC deserves serious consideration when users must communicate directly from ordinary browser tabs. Valhalla's implementation instead connects the browser to a native gateway on the same machine, and that gateway uses iroh upstream. This work does not demonstrate a browser-only iroh client or remove the local gateway requirement.

Libp2p also supports relayed connections and hole punching. Its [Circuit Relay specification](https://github.com/libp2p/specs/blob/master/relay/circuit-v2.md) defines relay reservations and resource limits; its [DCUtR protocol](https://github.com/libp2p/specs/blob/master/relay/DCUtR.md) coordinates an upgrade from a relayed connection to a direct one.

Valhalla already uses Malachite's libp2p networking for the public room directory and consensus. The private mailbox has a narrower job: connect to one selected host and exchange requests. Iroh fits that job without a replacement of the public consensus network. Using libp2p for both could consolidate dependencies, but would require a separate private-mailbox design and testing; this implementation makes no measured complexity or performance claim about that alternative.

### WireGuard and mesh VPNs

[WireGuard](https://www.wireguard.com/) carries network packets through an encrypted VPN. [Tailscale's connection documentation](https://tailscale.com/docs/reference/connection-types) describes direct UDP connections and relayed alternatives, all encrypted with WireGuard. A VPN can make an application's ordinary listener reachable across a private network and can serve several applications at once.

That is attractive for a team already managing such a network. For an invitation to one Valhalla mailbox, requiring each participant to enroll a device and maintain a separate network service adds another setup task. Iroh puts the connectivity library inside the application instead. A mailbox invitation still needs its own access token; transport connectivity alone never grants room membership.

## How a private message moves through Valhalla

The implementation keeps transport, storage, and group encryption separate. [Messaging Layer Security, or MLS](https://www.rfc-editor.org/rfc/rfc9420.txt), establishes group keys and protects room messages. The MLS specification assumes a delivery service; it does not make every member's machine reachable.

For a native sender and recipient, the path is:

```text
Sender encrypts a room message with MLS
                |
       iroh encrypted connection
       direct or through an iroh relay
                |
Owner's mailbox stores the ciphertext
                |
       recipient connects and fetches
                |
Recipient checks and applies the message
```

The browser adds a local step before the native connection: its worker talks to a loopback gateway using a browser capability. The gateway keeps the upstream mailbox credential separate and sends the request over iroh. The [gateway test](https://github.com/hraness/valhalla/blob/28a4f60dfa1c38265027abfadaba1284244d47a8/crates/vhalla-private-native/src/relay/http/tests.rs) exercises an actual HTTP-to-iroh exchange and rejects a wrong browser capability.

The [iroh adapter](https://github.com/hraness/valhalla/blob/28a4f60dfa1c38265027abfadaba1284244d47a8/crates/vhalla-private-native/src/relay/iroh.rs) uses the same mailbox permission and quota implementation as TCP/TLS. Limits cover connections, streams, request sizes, and deadlines. Changing transport therefore does not give a sender unlimited storage or permission to read another mailbox.

A successful network write also does not establish that a recipient applied the message. Valhalla tracks delivery separately and retries the same ciphertext after an uncertain result. Its [delivery rules and tests](/writing/delivery-specs-that-fail-on-purpose/) distinguish a mailbox storing a message from a recipient accepting it. This distinction matters when a host stores a request but the connection fails before the sender receives its response.

## Identity and authorization remain separate

A [private invitation](https://github.com/hraness/valhalla/blob/28a4f60dfa1c38265027abfadaba1284244d47a8/docs/iroh-private-rooms.md) carries the selected endpoint identity, mailbox namespace, participant token, and room offer. The namespace identifies the mailbox. The token grants mailbox operations. Room membership and agent grants decide what the participant may do with room contents.

The connecting client authenticates the host's endpoint key before sending the bearer token. That is why substituting an IP address or relay hint must not substitute the host's identity. Valhalla also binds saved delivery work to the endpoint key and mailbox namespace. Moving the same endpoint to another route can preserve queued work; changing the endpoint key or mailbox refuses reuse of the old queue.

Send an invitation through a confidential, authenticated channel to the intended recipient: it contains a bearer token and a secret room offer. Correctly authenticating a key from an attacker-supplied invitation would authenticate the attacker's endpoint. Iroh provides the key check; the application and its users decide which key they intended to trust.

Valhalla uses iroh's [Minimal preset](https://docs.rs/iroh/1.2.0/iroh/endpoint/presets/struct.Minimal.html) and configures the selected relay explicitly. It does not enable a public endpoint-address lookup service. Members receive routing information in the invitation. The integration does not publish a searchable directory of private rooms.

## Encrypted content still exposes connection metadata

The iroh relay forwards the encrypted connection between endpoints. It can observe who connects to it, endpoint identities, timing, and traffic volume. Valhalla also includes the opaque mailbox namespace in protocol negotiation. QUIC's initial handshake is not a place for secrets: [RFC 9001](https://www.rfc-editor.org/rfc/rfc9001.txt) explains that Initial packet keys can be derived by an observer.

Mailbox tokens are sent inside the authenticated connection, and room contents receive separate MLS encryption. The transport relay does not receive those tokens or room keys in plaintext. An operator who also participates in a room has that participant's access, regardless of where the mailbox runs.

This architecture does not provide anonymity. Direct peers expose network addresses to each other, relays can observe connections, and a mailbox operator can withhold or delete stored ciphertext. Encryption does not supply availability. Running a relay you control changes who operates that dependency; it does not remove its bandwidth, maintenance, or metadata responsibilities.

## What the implementation has tested

The [implementation report](https://github.com/hraness/valhalla/blob/28a4f60dfa1c38265027abfadaba1284244d47a8/docs/iroh-transport-plan.md) records local direct connections, host restart, invitation and queued-delivery behavior, credential refusal, persistent quotas, and HTTP gateway forwarding. These tests check the application around iroh as well as the connection itself.

An explicit [public-relay test](https://github.com/hraness/valhalla/blob/28a4f60dfa1c38265027abfadaba1284244d47a8/crates/vhalla-private-native/src/relay/iroh/tests.rs) disabled the client's UDP transport and checked that every observed path used a relay while sending and fetching synthetic ciphertext. That establishes a real public-relay path. A separate [two-runner qualification](https://github.com/hraness/valhalla/blob/28a4f60dfa1c38265027abfadaba1284244d47a8/.github/workflows/iroh-qualification.yml) then built one binary and exercised a host and client on distinct GitHub-hosted machines. It verified delivery, exact duplicates, wrong credentials and namespace refusal, fresh reconnect, forced-relay PUT/PAGE, durable reopen, and clean process exits.

The two runners establish independent machine placement, but they do not measure home or mobile NAT diversity. Long-running relay availability, sleep/wake and comparative latency or throughput measurements remain open work. The hosted Railway service uses TCP/TLS; a successful deployment there is not evidence of production iroh traffic. Iroh hosts also refuse the certificate and mailbox-generation maintenance operations that currently belong to the TLS workflow.

To run a new iroh host, follow the [source setup and host guide](/docs/private-rooms/). Preserve its endpoint private key across restarts and keep the mailbox running while members send or fetch. Choose explicit TLS when the deployment already provides a TCP listener or needs the TLS-specific maintenance tools.
