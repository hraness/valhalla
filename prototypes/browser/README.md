# Browser requester prototype

This pure-Rust model makes the browser a paired requester, not an ambient
owner. Every request must match the pinned origin, key fingerprint, nonce, and
scope. The real adapter must add non-exportable WebCrypto key custody, CSP,
strict `postMessage` origin checks, nonce rotation, and revocation; URLs and
`localStorage` must never carry bearer owner tokens.

Recommendation: browser UI can observe freely, but sensitive effects require a
paired origin and an explicit local gesture. A compromised origin is revoked,
not promoted into the owner trust root.

Run `cargo test --manifest-path prototypes/browser/Cargo.toml`.
