# Validator transport identity upgrade

The transport-authentication fix following PR #82 changes each validator's
libp2p PeerId. Deploy the corrected binary across a private validator set as one
coordinated maintenance operation. Existing consensus public keys, private
validator seeds, social identities, genesis parameters, committed history, and
room ownership retain their meanings.

## Why the identity changes

Earlier node builds computed a transport private seed from the public consensus
address. Anyone with the advertised validator public key could reconstruct that
transport key and impersonate its Noise identity. A matching `/p2p/` pin therefore
did not prove possession of the validator's secret. Consensus vote and proposal
signatures are separate checks; this flaw does not by itself forge those
signatures, but it invalidates the claimed transport authentication boundary.

The corrected node uses the validator's actual secret Ed25519 seed to own its
libp2p identity. Its expected PeerId is computed from the corresponding public
Ed25519 key using the standard libp2p identity encoding. Public planning commands
need only the public key. The node signs consensus messages and libp2p handshake
proofs using their existing distinct protocol preimages. Possession of a network
identity still grants no owner policy or host execution capability.

There is deliberately no fallback to the public-derived transport key. Mixed
old/new pinned nodes reject each other's PeerIds, so a rolling upgrade can lose
quorum or temporarily split connectivity. Do not remove peer pins or disable
`peers_only` to make a mixed-version deployment connect.

## Operator procedure

1. Select one corrected release/commit and verify its checksum and published
   build evidence. Agree on the maintenance window and expected genesis/archive
   fingerprints using the group's existing authenticated coordination channel.
2. Record each node's current committed height and genesis fingerprint. Stop the node
   cleanly before taking a consistent backup of its private node home and stores.
   Protect backups as secrets: `node.json` contains a validator seed. Never
   exchange node homes or private node configuration files between operators.
3. Upgrade all validators to the same corrected build. Keep their existing
   validator seeds, `KEY64@host:port` pins, shared parameters, journals, stores,
   and consensus WAL. This identity change does not require regenerating keys,
   resetting state, deleting the WAL, or changing the `VRW2` format marker.
4. Run the existing `rooms node-check` command from the operator runbook on each
   node. Compare the genesis/archive values again and record the new
   `node_peer_id`. If an external operational allowlist or saved multiaddr embeds
   the old PeerId, replace it with the new public readback. CLI consensus-key pins
   are recomputed automatically by the corrected binary; regenerate public
   Tailcat/overlay plans if they were saved for reference.
5. Restart the full set with closed, pinned peering. Check replica-backed
   `rooms status`, submit a normal authorized room-directory operation, and
   confirm the same committed height and expected room state across the set. Let lagging replicas
   recover from committed history; do not clear their state to force agreement.
6. On a disposable rehearsal network with at least four equal-power validators,
   stop one member, confirm the other three continue committing, then restore it
   and confirm catch-up to the same committed height and room state. A three-member equal-power set
   requires all three to decide; it does not tolerate one absent member.

If authentication fails, compare the binary revision, consensus public key,
new PeerId, pin, address, and actual network path. Retain useful logs and stop
operational activation if those identities disagree. Network reachability,
provider health, and consensus quorum are separate diagnoses.

## Qualification boundary

Source regressions cover key ownership and rejection of the legacy forged
identity. Loopback meshes can establish protocol behavior on that transport;
they do not qualify a multi-host VPN, DERP path, or Cloudflare edge path.
The managed overlay planners continue to report `live_qualified: false`.
Repeat the operator's real provider-path acceptance before making availability
claims about a deployed network. This document describes an upgrade procedure;
it is not evidence that any user's live validator set has been upgraded.
