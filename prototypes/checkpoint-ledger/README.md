# vhalla (valhalla): certified history reference

This disposable Rust experiment connects the bounded certificate decoder to the
actual `vhalla-ledger` root and history checks. It uses `no_std` + `alloc` and
introduces no new external runtime dependency. Production crates do not depend
on this prototype.

```text
certificate bytes -> bounded decoding -> configured-key signature verification
                                             |
local linear history -> derived root/height --+-> CheckedCheckpoint
                                                      |
                                               RecoveryAnchor
```

`CertifiedLedger::admit` creates `CheckedCheckpoint` only after the configured
signatures and the local current tip, realm, epoch, root, and height all agree.
Private fields and immutable projections prevent raw claims or signatures alone
from constructing or mutating this evidence. Failed admissions preserve history
and the previous certificate. Appended events remain untrusted staging data;
actor IDs are not individually authenticated, and payloads gain no authority.

## Realm mapping

The existing certificate format uses a string realm, while production uses
`RealmId(u128)`. This adapter uses exactly:

```text
vhalla/realm/u128/v1/ + 32 lowercase hexadecimal digits
```

For realm 42 the value is `vhalla/realm/u128/v1/0000000000000000000000000000002a`.
All 128 bits are preserved, including leading zeroes. The constructor checks the
exact spelling and epoch against the immutable trust policy; human room names,
case variants, and shorter numbers are not aliases. This is an internal mapping
decision, not a released wire-format commitment or a way to allocate realm IDs.

## Recovery boundary

Recovery takes snapshot bytes, certificate bytes, the owner's trust policy, and
a **separately retained anchor** obtained from a checked checkpoint. It verifies
the certificate again, requires the same trust-policy digest and exact pinned
checkpoint, replays the bounded snapshot, and validates that checkpoint against
the restored current tip.

This intentionally restores only the pinned certified frontier. Older or
divergent histories, uncertified suffixes, altered certificates, and changed
trust policies are rejected. Recovery does not truncate or roll forward. The
snapshot's embedded local checkpoint is validated but cannot nominate the pin;
it may trail the pinned tip, in which case the checked pin replaces it.

The anchor models an external trust boundary **in memory**. There is no anchor
serialization, disk I/O, crash durability, or guarantee that the caller retained
the newest anchor. An older matching snapshot, certificate, and old anchor can
still succeed. Tests deliberately demonstrate this limit. Real rollback
resistance requires protected anchor freshness and an atomic persistence and
recovery protocol; sealed Rust fields do not supply either.

## Run

From the repository root:

```console
cargo run --manifest-path prototypes/checkpoint-ledger/Cargo.toml --example recovery --locked
cargo test --manifest-path prototypes/checkpoint-ledger/Cargo.toml --locked
cargo clippy --manifest-path prototypes/checkpoint-ledger/Cargo.toml --all-targets --locked -- -D warnings
cargo check --manifest-path prototypes/checkpoint-ledger/Cargo.toml --target wasm32-unknown-unknown --locked
```

The example uses public fixed test keys and an in-memory restart. The WASM check
requires that Rust target and proves compilation only, not browser execution.

## Remaining work

Durable anchors, crash recovery, protected freshness, explicit trust rotation,
conflict retention, and network admission remain open. The model stores one
latest checked checkpoint and a bounded linear history; callers must retain
certificate bytes separately for recovery. It does not establish
global agreement, prevent malicious signers, authenticate each event author,
or authorize host effects. Untrusted appends can fill or advance the staging
history, so production transport must not expose them without admission policy.

Follow the [promotion gates](../../kb/plans/valhalla-promotion-gates.md) before
moving this composition into the production workspace or the steel thread.
