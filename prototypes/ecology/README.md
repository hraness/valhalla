# Ecology prototype

Small deterministic Platonik/Valhalla ecology model for composition gain,
resource flows, mutation, and lineage replay. Modeled work is a game metric,
not physical energy, intelligence, agency, or real-world value. `World::new`
canonicalizes member order and bounds organisms and abilities; `try_new` rejects
duplicate organism IDs before truncation. Replay digests are domain-separated
SHA-256 values, but cryptographic provenance and durable state remain future
work.
