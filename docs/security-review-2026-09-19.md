# September 2026 readiness review

This review started from `b5eddc014588063c0aadbea54dff66d8f11da08d`, after
the overlay-profile work in PR #82. It covers the maintained CLI, room-node
transport and certificate boundary, persistent journals and registries,
dependency graph, and release process. It is a code and test review, not an
independent protocol audit or a public-network qualification.

Valhalla remains experimental software for explicitly configured private
networks. These repairs do not qualify open membership, hostile validators,
browser participation, or a general public service.

## Repairs and their limits

- Transport identity must require the node's private key. A seed derived from
  the public validator address allowed anyone to reconstruct its former
  transport identity. Operators must follow the coordinated restart procedure
  in [the transport upgrade guide](transport-identity-upgrade.md).
- Proposal input must reject invalid rounds and bound streams, parts and
  retained bytes before accumulating them. Bounds do not establish fairness
  under sustained hostile traffic. Stream signatures bind the full header,
  including its proof-of-lock round, so a relay cannot poison retained metadata
  before the authentic header arrives. Consensus separately authenticates its
  signed proposal; the missing stream binding was not evidence of a forged
  consensus decision.
- Proposal recovery must retain each distinct value from a validator and round.
  Immutable per-value records prevent equivocation from overwriting earlier
  metadata, and local proposals reach durable storage before the engine reply.
  Recovery retains batches extending the committed frontier even when an older
  binary lost their metadata; it cannot reconstruct overwritten headers. A
  restarted proposer can re-stream its retained value with the exact requested
  round and its own authority. This does not bound a hostile validator's durable
  same-height history.
- Validator configuration must have distinct identities, positive powers,
  at most 64 members in canonical order, and a total power no greater than
  `u64::MAX / 3`. Direct library callers are checked before storage or networking
  starts, as well as through CLI configuration.
  Certificate consumers validate that configuration and use widened arithmetic;
  the engine itself also performs multiplication when checking its thresholds.
- A journal must sync each new file's containing directory before publishing
  its head. Decoder lengths are checked before narrowing on 32-bit targets,
  and disk reads are bounded before allocating. Fault tests establish ordering
  and retry behavior; they do not simulate every filesystem or physical outage.
- Registry persistence must preserve existing proof, counters and context.
  A greater revision alone is insufficient. A same-revision update is allowed
  only for additional evidence on an already counted support tuple, with all
  other canonical state unchanged. This preserves the existing application
  replay semantics. Local continuity checks are not consensus proofs.
- Private-network onboarding restores the exact shared archive into a separate,
  frozen genesis store. Subsequent owner posts must not replace a running
  network's genesis. [The product review](p2p-product-review-2026-09-19.md)
  records this lifecycle and the remaining usability work.
- An incompatible consensus WAL must be preserved. Committed application
  history does not replace the undecided votes and locks needed to prevent
  conflicting signatures after recovery. Runtime errors and operator guidance
  now require a compatible binary or a reviewed state-preserving migration.
- Release builders must stage the full distribution before one publisher
  makes it public. The publisher verifies checksums and downloaded bytes and
  checks the exact tag, main commit and successful CodeQL checks. Rust, Kani,
  desktop and website checks all participate in the aggregate gate.

## Dependency evidence

The initial audit used `cargo-audit 0.22.2` and RustSec database commit
`d5c17953a895cf19e8d3ce66eaa42b6fcfe1fb16`, fetched on 2026-09-19. It inspected
the root and desktop lockfiles and 49 prototype lockfiles, including the
separately retained native WebRTC reference. The older 2026-09-13 receipt
does not certify the current dependency tree.
The final gate also covers the vendored DNS adapter's standalone lockfile:
51 maintained lockfiles and one frozen historical reference in total.

The maintained root and browser interoperability lockfiles upgrade Rustls
from 0.23.44 to 0.23.45 for
[RUSTSEC-2026-0285](https://rustsec.org/advisories/RUSTSEC-2026-0285.html).
The DNS compatibility patch is documented in
[vendor/libp2p-dns](../vendor/libp2p-dns/README.md); it removes the
active Hickory 0.25 resolver affected by
[RUSTSEC-2026-0118](https://rustsec.org/advisories/RUSTSEC-2026-0118.html) and
[RUSTSEC-2026-0119](https://rustsec.org/advisories/RUSTSEC-2026-0119.html).

Cargo can retain inactive optional dependencies in `Cargo.lock`; metadata can
also include packages reached through inactive weak feature references. The
advisory gate keeps the raw findings and uses Cargo's complete, all-feature
dependency tree across platforms, crosschecked against metadata, to identify
active package versions. It retains the tree and metadata evidence as well.
An affected dependency becoming active must fail the gate; advisory identifiers
are not globally ignored.

The lockfile at
`prototypes/browser-records/interop/native-admission-reference/Cargo.lock`
still records Rustls 0.23.44. It is immutable, checksum-protected historical
evidence, explicitly not selected by any maintained build or listener. Its
advisory is reported rather than rewriting the reference bytes or claiming a
clean historical lockfile. Its reproduction instructions are not a supported
deployment path.

The raw audit also reports unmaintained transitive packages, including `paste`
in the runtime graph and several macro/Unicode packages in the desktop lock.
The desktop lock includes the GLib unsoundness advisory RUSTSEC-2024-0429 in
its Linux dependency metadata; the distributed menu-bar application targets
macOS. Those warnings remain maintenance obligations, not evidence of a
resolved advisory or a qualified Linux desktop product.

## Remaining qualification work

Public participation and open membership are still unsupported. The retained
social-record hard bound is 4,096 records (the CLI defaults to 1,024), without
semantic garbage collection.
A hostile validator's repeated signed proposals at one height still require
bounded durable-metadata accounting and a tested retention protocol that
preserves locked-value recovery; blindly pruning that history is unsafe.

Relayed-network qualification requires the explicit live harness and owned
network endpoints. Ordinary green CI does not imply that harness ran. End-to-end
latency, sustained throughput, peak process memory, browser memory and long-term
storage growth have not been established for arbitrary public workloads.
Private owner-controlled storage, platform filesystem guarantees, and the
unsigned developer-build distribution remain part of the operating boundary.
