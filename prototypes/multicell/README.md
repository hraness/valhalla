# Multicell prototype

Reference model for differentiated agents sharing a checkpoint while retaining
local budgets and failure domains. It tests graceful degradation and quorum
homeostasis. Accepted events form one bounded linear history; competing
branches are rejected, and checkpoint heads must be the current tip. A
domain-separated SHA-256 root is derived from that event history, membership
epoch, and current member state, so caller-supplied roots are verified rather
than trusted.

This remains a disposable local model: it does not implement signatures,
persistence, consensus, or durable receipt recovery. Production use would
need authenticated event receipts and an explicit distributed finality rule.
