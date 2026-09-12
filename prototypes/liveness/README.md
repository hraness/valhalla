# Liveness prototype

Reference model for leases, logical progress, suspicion, and reattachment under
partitions. A heartbeat or timeout is treated as an observation, never as proof
of life or authority transfer. This crate has no clocks, sockets, or failure
detector implementation.
Progress is monotonic within the model and clock rollback is ignored; owner
and epoch values are illustrative tokens, not signatures.
