# Global network roadmap progress

This page is the join surface for the public-network roadmap. A stage is green
only when its acceptance evidence is linked from the maintained plan; local
tests and a single-provider soak do not advance a global-network stage by
themselves.

| Stage | Outcome | Status | Exit evidence |
| --- | --- | --- | --- |
| 0. Measurement substrate | deterministic topology/workload generators, receipts, and budgeted Railway lane | in progress | replayable baseline and unattended-run watchdog |
| 1. Room event core | signed causal DAG, deterministic merge, gap repair, and mixed-version vectors | proposed | model checks plus native/browser conformance |
| 2. Multi-provider reachability | DHT/provider discovery after a verified bootstrap, peer exchange, direct transport, and relay fallback | proposed | independent bootstrap and NAT/partition matrix |
| 3. Custody and anti-entropy | regional/archive classes, replica manifests, erasure option, and recovery proofs | proposed | failure-domain loss and retrieval receipts |
| 4. Public testnet | independent operators run public rooms across regions and versions | proposed | 100-peer gate and public incident runbook |
| 5. Abuse and governance | quotas, admission puzzles, moderation, key rotation, and protocol evolution | proposed | adversarial workload and upgrade receipts |
| 6. Global qualification and stewardship | 1,000 then 10,000 peers with bounded churn, realm-key rotation, and measured convergence | proposed | scale charter gates and independent-host evidence |

The detailed scope, dependencies, recovery rules, and decision log live in the
[global-network plan](../kb/plans/valhalla-global-network.md).
