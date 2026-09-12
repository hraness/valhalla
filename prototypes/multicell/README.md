# Multicell prototype

Reference model for differentiated agents sharing a checkpoint while retaining
local budgets and failure domains. It tests graceful degradation and quorum
homeostasis; it does not implement signatures, persistence, consensus, or a
state-root derivation. Checkpoint roots and approval evidence remain caller
supplied model inputs.
