# Attestation prototype

This standalone crate defines a vendor-neutral evidence vocabulary for the
Valhalla design. It distinguishes portable software statements, hardware-key
evidence, and TEE/RATS evidence. Every statement binds a fresh verifier
challenge, subject, realm/room/purpose, and validity interval.

The crate deliberately performs no cryptography and contains no vendor SDKs.
`SignatureStatus::Verified` can only be set by an external verifier. The
portable kind must never be silently upgraded to hardware or TEE assurance, and
attestation evidence must not mint tool capabilities by itself. `disclose`
provides a privacy-preserving default for sharing evidence with peers.

Run with `cargo test --manifest-path prototypes/attestation/Cargo.toml`.
