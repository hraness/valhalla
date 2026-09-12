# Membrane prototype

A bounded realm boundary for hostile frames. Admission binds each frame to a realm context and epoch, declared capability, byte quota, bounded replay set, revocation state, and a global finite queue. Re-admitting a realm rotates its epoch and drops queued frames from the previous policy. Rejected frames are never dispatched.

This is not encryption, peer authentication, durable replay protection, or an OS sandbox. The replay set is intentionally in-memory; production needs authenticated transport and bounded persistent receipts.
