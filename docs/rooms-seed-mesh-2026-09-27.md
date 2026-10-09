# Rooms seed mesh, 27 September 2026

Three Railway validators reached the same committed state at height eight.
A fresh laptop observer started with one configured seed, discovered the
other two, and synchronized the complete history. An earlier laptop node
joined the voting set at height four, signed decisions at heights four
through six, and left the set at height seven.

The [recorded results](evidence/rooms-seed-mesh-20260927.json) include public
peer identities, deployment IDs, verified certificate signatures, and state
comparisons. All three seeds ran commit
[`9a9bd6a`](https://github.com/hraness/valhalla/commit/9a9bd6a7cce194bef2295f875c9b87ba70e0c7a8)
after [PR #199](https://github.com/hraness/valhalla/pull/199) passed its required
checks. Deployment preserved each node's configuration, committed stores,
and consensus WAL format.

## Observed results

Each validator had one vote. The signed decisions followed this schedule:

| Committed heights | Voting set | Votes required | Laptop evidence |
| --- | --- | --- | --- |
| 1–3 | Three seeds | Three | Outside the voting set |
| 4–6 | Three seeds and laptop | Three | Verified commit signature at each height |
| 7–8 | Three seeds | Three | Excluded by the committed schedule |

All eight certificates passed independent signature and quorum checks. The
committed schedule establishes the laptop's removal; its absence from a
certificate alone would not establish that it sent no vote.

At 21:25:02 UTC, seed-b proposed the value that committed at height eight,
round 113. The empty batch had been submitted only to seed-b. All three
seeds and both running laptop observers reached the same committed
frontier. Room, social, validator, and clock state stayed unchanged from
height seven. The read replica reported height eight with registry
revision seven, reflecting the difference between consensus progress and
an application update.

Journal bundle hashes can differ when a decision carries different valid
quorum certificates. State comparison used the committed frontier and the
room and social store pins, rather than requiring identical certificates.

After both laptop nodes stopped, another fresh observer joined with only
seed-a configured. It connected to seed-a at 21:28:36 UTC and authenticated
seed-b and seed-c through discovery within two seconds. It
synchronized to height eight and the same committed frontier. This check
used the deployed seeds with the earlier laptop processes offline.

## Connecting a reader

The [seed deployment recipe](../deploy/rooms-seed/README.md) describes the
shared network file, persistent storage, pinned peer keys, and public TCP
addresses. The endpoints used for this run were:

| Seed | Public endpoint |
| --- | --- |
| seed-a | `tokaido.proxy.rlwy.net:54453` |
| seed-b | `tokaido.proxy.rlwy.net:33412` |
| seed-c | `iriguchi.proxy.rlwy.net:33228` |

Use the matching public validator key from the recorded results when
configuring a `KEY@HOST:PORT` bootstrap peer. Set each seed's `ADVERTISE` to
its own public endpoint so discovery shares a reachable address. A reader
can start with one pinned seed and discovery enabled.

For a running local node, use `rooms status` with a separate replica home as
described in the [CLI instructions](../crates/vhalla-cli/README.md). That
command requires the `experimental-rooms-replica` feature; the seed image builds
only `experimental-rooms-node`.

All temporary laptop nodes stopped through SIGINT after verification. The
three persistent seed services remained online with `RUST_LOG=warn`.
Their node configurations, journals, and consensus WALs were preserved.

## Scope

This run used three services on one hosting provider and one physical
laptop. Multiple node processes on that laptop do not add independent
machines. The traffic consisted of configuration updates and the empty
height-eight batch; it did not exercise funded room creation.

Three equal-power validators require all three votes to decide. This run
does not establish tolerance of a seed outage, provider or regional
failures, network partitions, arbitrary NAT arrangements, or long-term
availability.
