# Discovery and bootstrap prototype

This prototype treats discovery descriptors as signed, expiring hints. A
trusted invitation supplies the realm and minimum protocol; a descriptor cannot
change either. Direct delivery is preferred, but an independently operated
relay is an explicit fallback. Invalid, expired, wrong-realm, and downgraded
hints fail closed.

Recommendation: ship multiple seed hints plus caller-provided invitations and
cached peers. Treat DNS, GitHub, HTTP, and relay listings as replaceable
bootstrap distribution, never as an authority or a required central service.

Run `cargo test --manifest-path prototypes/discovery/Cargo.toml`.
