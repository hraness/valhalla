# Valhalla room signature evidence

This portable `no_std + alloc` crate defines bounded signed records for
vhalla (valhalla) rooms. It supplies cryptographic evidence only. A valid record
does not prove current owner control, a live room grant, earned allowance, an
available slug or a finalized directory entry.

The owner is the maintained social `OwnerId`; the creator is an exact `AgentId`.
Room creation permissions use their own `GrantCreate`/`RevokeGrant` record family.
Social v1 `Rights::ALL` remains unchanged. Creation grants confer no room-update,
moderation, invitation, private decryption or host tool authority.

An exact `CreationIntent` binds the directory, realm, policy, initial settings,
owner and agent IDs and full keys, social and room-control bases, grant, slug,
description, owner slot, charge, expiry and nonce. The owner signs a dedicated
permit domain. After verifying that evidence, the agent signs a different domain
binding the exact permit and full genesis commitments. There is no circular hash
dependency. All content identifiers exclude signature representations.

`OwnerPermit::decode` and `SignedRecord::decode` produce immutable, structurally
checked evidence. Only strict full-key verification produces `VerifiedOwnerPermit`
or `VerifiedRecord`; private fields and compile-fail examples prevent unchecked
construction and payload mutation. Verified wrappers remain cloneable historical
evidence. They are never admission capabilities.

Frames start with `VHRM` plus version byte `1`, followed by one closed family tag,
a big-endian `u16` payload length, the canonical payload and fixed-width Ed25519
signatures. Tags are control `0`, creation proposal `1`, update `2` and intermediate
owner permit `3`. A proposal has owner then agent signatures; other frames have
one controller/owner signature. Permit frames cannot be decoded as complete room
records. Foreign input is rejected above 2,048 bytes before parsing. Slugs use
1–48 canonical lowercase ASCII letters/digits/hyphens, descriptions use 1–256
UTF-8 bytes without control characters, and unknown tags, alternate spellings,
trailing bytes and weak keys are rejected. All variable allocation has an explicit
bound; complete-frame size also has compile-time schema ceilings.

Owner-signed updates reference a full `RoomGenesisId` and exact previous room
record. They can change the description or request archival, never change the
slug or genesis owner. No API converts a full genesis into legacy `RoomId` routing
handles, executes these updates, admits creation, or constructs finalized state.

The next authority adapter must check stable affiliation, exact predecessor
history, current grant/retirement/rotation state, and policy scope against the
directory's agreed control snapshot. R3 must establish the freshness and finality
of that snapshot; a locally complete social archive is insufficient. Numerical
prices, balances, expiry evaluation, slug allocation, atomic slots, durable state
and network consensus remain outside this crate.

Focused checks after workspace integration:

```sh
cargo test -p vhalla-rooms --locked
cargo clippy -p vhalla-rooms --all-targets --locked -- -D warnings
cargo check -p vhalla-rooms --target wasm32-unknown-unknown --locked
```
