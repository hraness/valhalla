# Public peer advertisements

This portable no_std + alloc crate defines one bounded signed route-hint format.
It opens no listeners, discovers no peers, resolves no names, persists no state
and activates no public network. The signer claims an application identity,
network, sequence, lifetime, protocol and services at up to four endpoints.
A valid advertisement grants no validator admission, room membership, posting
rights, social authority or host effects. It does not prove that the signer
controls any advertised endpoint or that a service is available.

The receiving client obtains its 32-byte network identifier independently.
Accepting an arbitrary self-signed advertisement as the trust root would defeat
that separation. The application key is a full Ed25519 public key, separate from
validator admission and transport identity.

## API and trust boundaries

- Endpoint::parse accepts a bounded canonical route without dialing.
- UnsignedAdvertisement::new checks proposed content and freezes it.
  signing_bytes and attach_signature support an asynchronous external signing
  provider; sign_with_key supports native custody without exporting a seed.
- PeerAdvertisement::decode checks canonical structure, counts, routes and keys.
  unverified_claims is explicitly unauthenticated; encode does not verify.
- PeerAdvertisement::verify checks strict domain-separated Ed25519 signatures,
  the independently supplied network, exclusive expiry, future issuance skew,
  signed lifetime and optionally a retained descriptor's sequence.
- VerifiedAdvertisement has private fields and only immutable accessors.
  It records the evaluation time, not ongoing freshness or permission to dial.

Persist the greatest verified descriptor for each (network, full application
key). Supply its immutable SequenceAnchor as previous when verifying a
replacement: only a strictly larger sequence succeeds; equal-sequence duplicates
and conflicts both fail. VerifiedAdvertisement::sequence_anchor obtains that
floor. After restart, decode the retained signed descriptor and call
PeerAdvertisement::restore_sequence_anchor with the expected network. This
strictly authenticates only a sequence floor, without granting freshness or
exposing routes through the anchor. Expired evidence still supplies the floor. Do not delete that floor
when an endpoint expires or when a peer cache evicts its active route. None is
appropriate only when no earlier evidence is known; this crate cannot detect a
host discarding or rolling back its history. Sequence exhaustion never wraps.
Recheck a cached descriptor against fresh time without treating that freshness
check as insertion of a new sequence.

The caller supplies a trusted, nondecreasing Unix-seconds clock. Expiration is
exclusive and receives no skew grace. Issuance may be at most the policy's future
skew ahead of now. The hard signed lifetime is 86,400 seconds and hard future
skew is 300 seconds; callers may lower either. No implicit clock or default
trust policy exists.

## Canonical wire

All integers are big endian. The exact unsigned bytes are:

    VHPA | version:u8=1 | network:32 | application_key:32 |
    sequence:u64 | issued_at:u64 | expires_at:u64 | protocol:u16=1 |
    capabilities:u32 | endpoint_count:u8 |
    repeated(endpoint_length:u16 | endpoint_ascii_bytes)

Append one 64-byte Ed25519 signature. The signed transcript prefixes those
unsigned bytes with the ASCII domain vhalla/public-peer-advertisement/v1 and
one NUL byte. Version 1 capabilities are READ=1, PUBLISH=2 and SUBSCRIBE=4;
zero/unknown bits fail closed. These are service claims, not implemented
services or grants.

There are one to four endpoints in strictly increasing ASCII byte order.
Duplicates and alternate spellings are errors, never silently normalized.
The frame is bounded to 1,324 bytes before parsing, each endpoint to 288 bytes,
and allocations remain under those fixed bounds. Unrecognized versions,
trailing bytes, weak keys and inconsistent lengths are rejected. Verification
performs one strict Ed25519 check for a structurally valid advertisement; the
caller must impose total signature, connection and peer-count budgets.
There is deliberately no unbounded peer book or implicit auto-eviction policy.

## Routes and future dialer requirements

Routes use exact lowercase https or wss, an explicit nonzero decimal port without
leading zeros, and the fixed /vhalla/v1 API base. Credentials, queries, fragments,
percent escapes, alternate paths, zone IDs and trailing slashes are forbidden.
DNS is lowercase ASCII, at most 253 bytes, at least two labels, each at most
63 bytes, and has an alphabetic final label. Unicode and punycode final labels
are outside this initial codec. Common special/local namespaces are rejected.

Literal IPv4 addresses use canonical dotted decimal. The conservative filter
rejects special/private/shared/link-local/loopback/documentation/benchmark,
multicast and reserved ranges. IPv6 uses canonical compressed lowercase syntax
inside brackets; the accepted subset is 2000::/3 excluding 2001::/23,
2001:db8::/32, 2002::/16 and 3fff::/20. This intentionally excludes some globally
reachable special-purpose assignments and translation mechanisms.

The prefix policy was checked against the
[IANA IPv4](https://www.iana.org/assignments/iana-ipv4-special-registry/) and
[IANA IPv6](https://www.iana.org/assignments/iana-ipv6-special-registry/) registries;
DNS exclusions also consult the
[special-use domain registry](https://www.iana.org/assignments/special-use-domain-names/).
A syntactically accepted name or address is not proof of public reachability.

A future dialer must enforce private-address and local-network exclusions on
every resolved address and actual connection, pin its selected resolution
against rebinding, disable redirects or revalidate each redirect, bound DNS/
TLS/handshake work, and authenticate both TLS and the advertised application
identity in a fresh protocol session. It must never forward ambient cookies,
authorization headers or other origin credentials to discovered routes.
Browser fetch/WebSocket APIs do not expose all DNS/socket controls; a browser
adapter must state how its platform and serving architecture enforce that
boundary instead of claiming this parser provides SSRF protection.

Public discovery, proof of endpoint control, serving adapters, browser custody,
durable peer tracking, multi-provider failover and end-to-end qualification
remain separate work.
