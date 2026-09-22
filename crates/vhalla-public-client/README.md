# Portable certified room client

This crate verifies and replays the maintained room-directory application from
independently pinned genesis. It performs no network, browser, filesystem or
background work. Its application state is the existing bounded social Archive
and room Registry, so this is a full application replica rather than a succinct
proof-only light client.

## Trust and bootstrap

Bootstrap::from_genesis accepts an existing Genesis and complete validator-set
activations. It checks archive realm/limits against the supplied configuration,
directory policy, at most 256 eligible owners, at most 64 activation sets and
64 validators per set. Validator identities must be unique by full key AND
derived consensus address; weak keys, zero powers and totals above u64::MAX / 3
are rejected before engine-set construction. The first set activates at height
1. Later activations replace the complete set.

The version-1 canonical frame contains:

    VHPB | version:u8=1 | realm:u128 | directory:32 |
    policy(base:u64, window:u64, max_in_window:u16,
           support_epoch:u64, lifetime_rooms:u32) |
    limits(7 x u32 in Archive::Limits field order) |
    eligible_count:u16 | eligible_owner_ids:32*count |
    activation_count:u8 |
      repeated(from:u64 | validator_count:u8 |
               repeated(full_key:32 | power:u64)) |
    snapshot_length:u32 | complete_canonical_signed_genesis_snapshot

All integers are big endian. Eligible IDs, activation heights and each set's
full public keys have strictly increasing canonical order. Constructors normalize
equivalent input ordering, while decoders reject noncanonical wire ordering.
The complete archive retains the existing hard 4,096-record/8,192-byte record
ceiling; MAX_BOOTSTRAP_BYTES includes that bound plus the finite configuration.

Two domain-separated SHA-256 commitments have distinct jobs:

- pin() hashes the complete canonical frame under
  vhalla/public-bootstrap/v1 followed by NUL. It binds the entire trusted
  activation schedule AND exact signed genesis evidence.
- network_id() hashes the same canonical shape with ONLY the first activation
  under vhalla/public-network-origin/v1 followed by NUL. It is stable when a
  trusted operator appends future rotations. Changing immutable genesis or the
  initial validator set changes the network.

These are intentionally distinct from the CLI's older configuration-only
genesis fingerprint. Bootstrap::decode(raw, expected_pin) checks the byte bound
and an independently retained content pin before expensive snapshot signature
admission. A hash received beside its bytes from the same untrusted server is
not an independent trust anchor. No discovered route can change the trusted
genesis or validators. There is no dynamic configuration-update API here:
a new schedule requires an explicitly trusted new bootstrap and replay.
Appending activations must preserve the previously trusted origin and committed
history; this crate does not infer operator approval.

## Verification and persistence contract

CertifiedClient::new consumes a Bootstrap matching an independent full pin.
prepare(network_id, bundle_bytes) checks one next-height bundle without changing
visible state. It verifies the canonical batch, exact parent frontier, value,
height-specific validator quorum, signed application replay and every journal
field. It reconstructs the exact BundleParts used by the maintained producer,
including policy/configuration, control and debit annotations, and requires
byte-for-byte equality. A valid batch certificate alone does not authenticate
arbitrary annotations, so altered annotations are rejected.

The returned move-only VerifiedCandidate has private fields and exposes immutable
bundle bytes/identity, stable network ID, exact configuration pin, and base/next
frontiers. Persist those bytes and the scoped next frontier in one host-owned
transaction, guarded by the base frontier. Only after that succeeds call
commit_after_persist(candidate). Calling it is the host's explicit acknowledgement
of storage completion; this portable crate cannot observe IndexedDB or fsync
and does not fabricate a durable receipt. A failed/uncertain transaction must be
reconciled from retained bytes before advancement. Dropping a candidate changes
nothing. Commit rechecks network, complete configuration and base frontier.

Two candidates may be prepared at the same frontier, but only one can install;
the other becomes stale. A candidate from a different network/configuration
cannot install. Transfer between clients with the same exact pinned configuration
and base frontier is intentionally safe. No unchecked snapshot/frontier setter
exists. Restart recovery replays retained certified bundles in order from pinned
genesis, one bounded operation at a time. Retain the bootstrap pin independently
and scope persistent data by network and configuration. The host must protect its
last accepted frontier against rollback and reconcile storage uncertainty.

Old, duplicate and reordered heights return Height without changing the state
or retaining a queue. Resume fetching the exact next height from another peer.
A serving peer's head is an observation, not proof of global freshness or that
nothing newer exists. Current-validator signatures are not network completeness.

## Limits and qualification

One prepare call accepts at most the journal's existing 1 MiB bundle limit,
a 48 KiB batch, at most 32 records per class and 64 certificate signatures.
Invalid certificates are rejected before application replay. The caller owns
total response, verification, retry and memory budgets across calls; it also
bounds outstanding candidates, connections, retained disk history and bootstrap
work. Immutable typed APIs do not automatically make an unbounded host loop safe.

Tests construct actual Ed25519 quorum signatures and real signed social/room
fixtures. They cover staged publication, cancellation, replay and rotation,
forged certificates, annotations and results, mismatched scope and frontier,
duplicate/reordered multi-peer delivery, incremental restart, hostile lengths,
canonical bootstrap order and configuration limits. Storage in these tests is
an in-memory retained-byte vector, not browser persistence qualification.

HTTPS serving, signed endpoint challenges, browser key custody, IndexedDB,
provider selection, public activity/membership binding, long-term archive
retention and live browser/network qualification remain separate work.
