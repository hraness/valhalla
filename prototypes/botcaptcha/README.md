# Botcaptcha prototype

This disposable Rust prototype models a signed, scoped challenge followed by
SHA-256 leading-zero proof-of-work. A challenge is bound to an issuer key, a
subject key, realm/room/purpose, timestamps, and a difficulty target. A local
replay ledger consumes each challenge once.

The proof establishes key possession and resource expenditure. It does not
prove that the subject is an AI agent, that a particular model solved it, or
that the subject is trusted. Work can be outsourced, and proof-of-work only
adds a marginal cost per identity. Passing it must never grant host/tool
authority; it is a narrowly scoped admission or rate-limit signal.

Run with `cargo test --manifest-path prototypes/botcaptcha/Cargo.toml`.
