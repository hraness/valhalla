# Dead-device recovery policy experiment

This finite model tests one unresolved design question: can an account backup,
history archive, relay retirement claim and elapsed time establish that the
previous device has stopped using an existing private room?

Run without dependencies:

```console
python3 prototypes/device-recovery-policy/model.py
python3 -m unittest discover -s prototypes/device-recovery-policy -p 'test_*.py'
```

The experiment enumerates all 5,461 observation sequences of length zero through
six. It pairs each with two worlds: the previous device is permanently lost, or
it remains active behind a partition. The recovering client sees identical
observations. A proposed two-timeout recovery rule authorizes a replacement in
both worlds. Increasing the timeout or trusting an unauthenticated relay status
does not remove that counterexample.

**Decision:** do not implement unilateral live recovery under existing anchors.
Their account backup authorizes neither a predecessor control nor global
retirement. Offer these explicit paths instead:

- A live current owner admits a fresh device; it starts fresh MLS custody and
  receives only policy-authorized post-join content. A live predecessor can hand
  owner authority to an enrolled current successor using the signed proof chain.
- An archive remains read-only history. It never resets counters, opens a copied
  ratchet, or proves that a previous device stopped.
- If no authorized owner can act, create a distinct room and fresh device under
  a new anchor, and explicitly invite members. Each participant must accept that
  new authority. This does not revoke or erase the old room.

The model does not implement cryptography, prove distributed consensus, enforce
device freshness, simulate MLS, or test filesystem durability. The live-owner
input abstracts an already authenticated admission, not a new runtime flag.
The executable result is a counterexample to timeout recovery, not production
qualification of the positive paths.

An eventual same-anchor emergency-recovery feature needs authority agreed at
anchor creation plus a specified ordering/fencing service and offline-client
rules. Trustee signatures alone do not tell an isolated old client that its
authority changed. Before choosing such a protocol, specify the allowed
availability loss during partitions, trustee failure assumptions, proof retention,
fresh-device key distribution, expiry, and the behavior of returning predecessors.
Model competing requests, partial trustee availability and interruption at each
durable step; then test the real cryptographic and storage implementation.
Existing anchors must never acquire that recovery policy implicitly.
