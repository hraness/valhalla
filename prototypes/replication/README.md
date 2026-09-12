# Replication and history prototype

This prototype tests optional replicated history without pretending that gossip
is durable storage. Replicas merge signed-event identities idempotently,
provide deterministic `(lamport, author, event_id)` ordering, and enforce
count/byte retention bounds. A receipt explicitly says `stored` while keeping
`durable` false.

Recommendation: ship live delivery and bounded local history first. If durable
replication is added later, expose separate accepted/stored/durable/completed
states, retain event IDs across restart, and make retention/privacy policy an
explicit capability. Never let a relay receipt imply task completion.

Run `cargo test --manifest-path prototypes/replication/Cargo.toml`.
