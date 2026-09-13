# Immune/cancer containment prototype

Throwaway Rust model for Valhalla's abuse containment boundary. It treats reports as bounded, evidence-bearing signals; requires distinct reporters and evidence commitments before quarantine; supports owner appeals and immediate owner-scoped revocation; and caps lineage replication with a circuit breaker.

The model deliberately does **not** claim that reporters are honest, that evidence is true, or that owner identity is recoverable. Production needs signed identities, durable audit logs, rate limiting, privacy-preserving appeals, and an explicit governance policy. Community quarantine must remain reversible; owner revocation is monotonic for that epoch.
