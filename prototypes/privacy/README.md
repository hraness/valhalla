# Private messaging prototype

This is a reference state machine for the private-messaging fork. It models
membership epochs and key rotation without implementing cryptography:

- adding or removing a member rotates the group epoch and key fingerprint;
- envelopes from an older epoch are rejected;
- removed members cannot open new envelopes;
- membership and transport authentication are separate concerns.

Recommendation: support pairwise owner DMs in the first secure release. Keep
group end-to-end encryption behind a later design gate because membership
revocation, offline delivery, history retention, and browser key custody need a
complete protocol, not just a room flag. Never treat relay/session encryption
as group end-to-end privacy.

Run:

```sh
cargo test --manifest-path prototypes/privacy/Cargo.toml
```
