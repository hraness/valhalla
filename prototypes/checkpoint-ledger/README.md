# vhalla (valhalla): certified history reference

This disposable Rust experiment connects the bounded certificate decoder to the
actual `vhalla-ledger` root and history checks. Its default core uses `no_std` +
`alloc`; an optional Unix backend uses Rust's standard library. Both reuse the
existing cryptographic dependencies. Production crates do not depend on this
prototype.

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

The direct anchor API models an external trust boundary **in memory**. It has no
raw constructor or serialization and does not prove the caller retained the
newest anchor. An older matching snapshot, certificate, and old anchor can still
succeed. The persistence layer below adds storage, but protected anchor freshness
remains an external requirement.

## Persistence transaction

`persistence::PreparedCommit` validates a certified snapshot and binds it to an
exact predecessor `Pin`. A later checkpoint must use the same realm, epoch, and
trust policy and contain the previous checkpoint's independently checked root
and height. A higher signed fork is rejected. Bootstrap uses `None` explicitly;
it cannot replace an existing pin.

`commit` writes a bounded immutable snapshot/certificate bundle, syncs its bytes
and discoverable name, then conditionally advances the **full** predecessor pin.
The pin contains a local generation, bundle SHA-256, checkpoint, and trust digest.
Generation overflow and stale writers fail closed. No automatic compaction or
deletion occurs. A lost acknowledgement can be retried with the same prepared
operation; an indeterminate pin write requires reconciliation, not an assumed
abort. Even when the target pin is already visible, retry repeats the bundle and
pin durability operations before reporting `AlreadyCommitted`.

`load` reads only the local backend's pin, loads that exact bundle, checks its
digest, and re-verifies certificate and history. Missing or corrupt current data
is an error; it never selects an older bundle from a directory scan. A concurrent
writer may advance after the initial pin read, so the result is a consistent
captured frontier, not a promise to return the newest state at completion.
`Pin::decode` parses plain data and supplies no authentication or authority.

Canonical records use domain strings, version `1:u16`, and big-endian integers:

```text
bundle = "vhalla/checkpoint-store/bundle/v1" || version
         || snapshot_length:u32 || snapshot || certificate_length:u32 || certificate
pin = "vhalla/checkpoint-store/pin/v1" || version || generation:u64 || bundle_hash:32
      || realm:u128 || epoch:u64 || trust_digest:32 || head:32 || root:32 || height:u64
```

Pins are exactly 200 bytes. Bundle fields retain the underlying snapshot and
certificate hard bounds; decoding checks lengths before slicing or allocating.
The test vectors use Python `struct`/`hashlib` independently: a bundle containing
snapshot bytes `1,2,3` and certificate bytes `4,5` is 48 bytes with SHA-256
`4d2152067860e0d8e9b9cf33336db7b6b2fede196f1ae744f3fceddc68d91929`.
A pin with generation 9, bundle bytes all 1, realm 42, epoch 7, trust bytes all 2,
head bytes all 3, root bytes all 4, and height 5 has SHA-256
`829b308a1ee954cdeb8a77538ee6808ede66ea9afa529244fc79495881880a64`.

## Native storage profile

The `native-store` feature exposes `file_store::FileStore` on Unix. It requires
Rust 1.89 or newer for standard-library [file locking](https://doc.rust-lang.org/std/fs/struct.File.html#method.try_lock).
`create_new(path, max_bundles)` refuses existing directories; `open` requires an
existing store. One OS lock is held for the adapter's lifetime. The directory
must be private, operator-controlled, and on a filesystem supporting file locks,
hard links, atomic rename, and file/directory synchronization. Directory and file
modes are checked as 0700 and 0600; symlinks and unexpected entries are rejected.
Ownership and protection of ancestor paths remain the caller's responsibility.

Bundle publication syncs a temporary file, atomically links its immutable digest
name, then syncs the directory. Pin publication syncs a temporary file, renames
it, and syncs the directory. Configured capacity is 1–64 bundles and includes
orphans; exhaustion requires explicit recovery/retention work. There is no
network-controlled path selection or automatic bundle pruning.

This profile exercises crash-consistent API ordering. It cannot detect rollback
or deletion of a pin by someone controlling the disk, nor coordinated replacement
of the pin and all its matching bundles. Tests explicitly demonstrate that limit.
Physical power-loss behavior, non-Unix storage, protected freshness hardware or
witness services, and third-party storage adapters are not qualified here.

## Run

From the repository root:

```console
cargo run --manifest-path prototypes/checkpoint-ledger/Cargo.toml --example recovery --locked
cargo test --manifest-path prototypes/checkpoint-ledger/Cargo.toml --locked
cargo clippy --manifest-path prototypes/checkpoint-ledger/Cargo.toml --all-targets --locked -- -D warnings
cargo check --manifest-path prototypes/checkpoint-ledger/Cargo.toml --target wasm32-unknown-unknown --locked
cargo test --manifest-path prototypes/checkpoint-ledger/Cargo.toml --features native-store --locked
cargo clippy --manifest-path prototypes/checkpoint-ledger/Cargo.toml --all-targets --features native-store --locked -- -D warnings
```

The example uses public fixed test keys and an in-memory restart. The WASM check
requires that Rust target and proves compilation only, not browser execution.
The feature-enabled suite also writes a newly created private temporary store,
closes it, reopens and verifies certified history, advances the pin, and reopens
again. Fault-model tests distinguish visible and durable data at every commit
step, including failed syncs, lost acknowledgements, and writers racing at CAS.

## Remaining work

Protected pin freshness, physical crash qualification, explicit trust rotation,
conflict retention, compaction, and network admission remain open. Direct ledger
users must retain certificates separately; the persistence layer bundles them
with each stored snapshot. Neither establishes
global agreement, prevent malicious signers, authenticate each event author,
or authorize host effects. Untrusted appends can fill or advance the staging
history, so production transport must not expose them without admission policy.

Follow the [promotion gates](../../kb/plans/valhalla-promotion-gates.md) before
moving this composition into the production workspace or the steel thread.
