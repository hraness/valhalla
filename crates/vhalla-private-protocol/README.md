# Private-room protocol records

This portable `no_std` crate defines bounded, canonical private-room records and
strict Ed25519 attribution. It supplies no MLS ratchet, membership database,
transport, public-directory entry, host execution, or automatic recovery.

`Verified*` means **signature and format only**. A valid signature from a key that
claims to be an owner does not make that key the room's current owner. Keep that
authorization check in the stateful adapter, against an independently selected
anchor and retained membership/control state.

| Record | Signed by | Binds |
|---|---|---|
| `RoomAnchor` | Owner account | Full private room ID, initial owner device, fixed suite and policy |
| `DeviceEnrollment` | Account | Exact device signature key and explicit validity interval |
| `Invitation` | Claimed owner device | Full room/anchor, recipient account/device, exact KeyPackage digest, nonce, validity and required control floor |
| `OwnerControl` | Claimed owner device | Full room/anchor, exact predecessor, next sequence/epoch, Commit digest and exact membership delta or explicit owner update |

Every record has separate `Unsigned*`, `Signed*` and `Verified*` types. Structural
decode does not create a verified wrapper. Signing and signature attachment are
typed and must match the exact claimed key. The full signed anchor determines its
anchor ID; private scope never truncates or reuses public directory identifiers.

Version 1 fixes RFC 9420 suite `0x0001` and owner-device-controlled policy `1`.
Complete signed frames are at most **4096 bytes**. A control contains at most
**16 total additions/removals**, sorted by full device key, with no duplicate
device, invitation or KeyPackage and no add/remove overlap. An empty membership
delta must use explicit `OwnerUpdate`; that does not authorize device-key handoff.
Counts are checked before allocation. All identifiers/nonces are full and nonzero;
invalid or weak Ed25519 keys, unsupported versions and trailing data are refused.

KeyPackage, Commit and Welcome digest helpers hash nonempty exact artifacts up to
**128 KiB**, using separate domains. They do not parse or verify MLS. Use the exact
chosen bytes consistently: the current MLS adapter prototype uses bare TLS
KeyPackage bytes and MLS-wrapped Commit/Welcome bytes.

For example, a custody implementation can sign one typed enrollment without
exposing a generic message signer or generating any default seed:

```rust
use ed25519_dalek::SigningKey;
use vhalla_private_protocol::{
    DeviceEnrollmentClaims, Error, Key, SignedDeviceEnrollment,
    UnsignedDeviceEnrollment, Validity,
};

fn enroll(
    account: &SigningKey,
    device: Key,
    validity: Validity,
) -> Result<SignedDeviceEnrollment, Error> {
    UnsignedDeviceEnrollment::new(DeviceEnrollmentClaims {
        account: Key::from_bytes(account.verifying_key().to_bytes())?,
        device,
        validity,
    })?.sign(account)
}
```

The caller must independently retain the correct custody key and exact anchor,
validate enrollment-to-owner/device roles, check explicit half-open validity
against a trusted nondecreasing clock, inspect actual MLS credentials/committer
and every staged proposal, preserve parent gaps/forks, and consume invitations
once in the same transaction as successful join. No validity defaults or trusted
clock are invented here. Key-only restore must not reset ratchets or control
floors. Signed text, URLs and these records never authorize host execution.

Eight adversarial tests cover exact round-trips, every truncation and one-byte
mutation, context/artifact binding, weak keys, strict suite/policy, clock edges,
control exhaustion, count/order/duplicate/overlap refusal and artifact budgets.
A compile-fail test prevents construction of a `VerifiedInvitation` from a merely
decoded record. Native tests, strict all-target Clippy and wasm32 checking pass:

```sh
cargo test --locked -p vhalla-private-protocol
cargo clippy --locked -p vhalla-private-protocol --all-targets -- -D warnings
cargo check --locked -p vhalla-private-protocol --lib --target wasm32-unknown-unknown
```

Run through the repository's required host scheduler and exact toolchain. The
isolated [OpenMLS qualification](../../prototypes/private-rooms-mls/README.md)
exercises real crypto separately. Stateful private-room authorization, real
native/IndexedDB atomic storage, private relay and client integration remain
separate gates; this crate is not a finished private-room client. See the root
[security policy](../../SECURITY.md) for current readiness and private reporting.
