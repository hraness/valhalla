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

## Rotation reference (not activation)

**Agent-decided, owner may revisit (2026-10-12):** model the next trust transition
only as a checked, volatile observation. `RotationObserver` borrows a
`CertifiedLedger` whose certificate still matches its current tip and binds the
old policy digest to that checked certificate. The caller supplies the complete
old and proposed new policies from its own configuration, not from the incoming
certificate. The new policy must name the same realm and exactly the next epoch.
A shared ledger borrow prevents appends while an observer is alive; when history
advances, discard the observer and check the new tip again. This does not prove
that a separately retained old pin is fresh or protected against rollback.

The reference format is **not** a released wire version. It uses fixed-width
big-endian fields, version `1:u16` and full Ed25519 public-key identifiers:

```text
statement = "valhalla/checkpoint-ledger/rotation/v1" || version
          || realm:u128 || old_epoch:u64 || next_epoch:u64
          || old_head:32 || old_derived_root:32 || old_height:u64
          || old_policy_digest:32 || new_policy_digest:32
old_signing_transcript = statement || 0:u8
new_signing_transcript = statement || 1:u8
certificate = statement || old_count:u16 || (sorted old_key:32 || signature:64)*
                        || new_count:u16 || (sorted new_key:32 || signature:64)*
```

Both quorums sign the **same** transition with different role bytes; overlapping
members must sign twice. The verifier checks every signature, rejects unknown,
duplicate and unsorted keys, short quorums, wrong realm/epoch/frontier/digests,
truncated/extra bytes and oversized input (32 KiB hard limit, at most 128 signers
per side). It retains at most 2–8 different valid transitions as full canonical
certificates. A valid retry of the same *statement* is idempotent even if it uses
a different valid signer subset. A second distinct valid statement is an
explicit conflict, not a candidate chosen by arrival, height or timeout. At
capacity, a further distinct valid statement permanently blocks that observer
without evicting prior evidence. A fresh in-memory observer is **not** recovery
from a conflict: preserving conflicts across restarts needs a separate store.
`Recorded` is only an observation, not permission to install a policy or reset
actor sequences. No transition signing, new-epoch genesis, persistence, physical
durability, independent witness custody, protected pin CAS, policy activation,
consensus, host effect or rollback-resistant conflict archive is provided.

The fixed transcript test is independently generated with Python `hashlib` and
big-endian integers, using OpenSSL to derive public keys from **public test seeds**
`[1,2,3]` and `[4,5,6]`. A one-event ledger with realm 42, epoch 7, actor 1,
sequence 1 and payload `genesis` produces head
`28c8de9d35d1e0383eedfdc4a5f50e6f88b7174bbd4c877d21666212599faec4` and root
`5a506f8ad7d5e85d97aaa80a8fcfb5b3710d8c41207ec4d1ae7fd066cf0e43fc`.
Old and new configured policy digests are respectively
`55723a12b7f2984c17dacee58bef3c94bda92181b881bc52166a0f1b8ba96404` and
`d052843ba5f6e0d69b3e8016b0effbaed38cc0e3fb184b7db701840f2b523168`.
The 209-byte role-bound transcripts have SHA-256
`55f6aa8bd4e66063b97e665f9c37ecbaf1d582bcf55879cd81b439cbbb1fb5a8`
(old) and `2a1a890c2213cdfa6a10a3284848810e0914f13d7d9380fc3b22add4912b2b10`
(new). This checks Rust transcript framing, not external certificate verification.

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

`load` is **legacy/unprotected**: it reads only the local backend's pin, loads
that exact bundle, checks its digest, and re-verifies certificate and history.
Missing or corrupt current data is an error; it never selects an older bundle
from a directory scan. A concurrent writer may advance after the initial pin
read, so the result is a consistent captured frontier, not a promise to return
the newest state at completion.
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

## Protected-pin reference contract

**Agent-decided, owner may revisit (2026-10-11):** for guarded recovery,
choose a separately controlled owner-host, monotonic and durable **full-pin**
witness. A `PinWitness` supplies a captured expectation containing generation,
bundle digest, checkpoint and trust-policy digest. `load_protected` first requires
that independent expectation, then requires exact equality with the local pin
before reading and re-verifying its one bundle, certificate and history. A
missing, stale or substituted local pin (even alongside its matching old
bundle), changed policy, corrupt bundle, absent witness or unavailable witness
refuses without a model, write, fallback or repair. The native/file store alone
is not a witness; a parsed `Pin` cannot establish freshness.

The witness here is an **independent deterministic test double**, not a service
or production storage adapter. The trait contract alone cannot prove isolation,
monotonicity, durability or the authenticity of its implementer.
The `protected_commit` module adds a one-step write and intent reconciliation
experiment under a separate `FencedWitness` trait; `PinWitness` still has no
protected write contract. The experiment cannot prove that a test-double host
keeps a durable, isolated monotonic pin or that physical sync survives power
loss. An adversary controlling both witness and disk can still coordinate
rollback. A witness advance after capture can also make this read stale; callers needing a latest-at-completion guarantee must establish
a separate snapshot/serialization protocol. Physical power-loss behavior,
independent-host custody and live availability require separate qualification.

### Protected two-store prototype contract

**Agent-decided, owner may revisit (2026-10-11):** the security/recovery
integration lane specifies the owner-host contract exercised by the model and
by `protected_commit` with `FileStore` and an independent witness test double.
Legacy `commit`, `load`, `load_protected` and all production entrypoints remain
unchanged. Calling legacy `commit` on a protected store would bypass the witness;
this prototype does not enforce access isolation between the two APIs.

- Provision a separately controlled, owner-identified host and an explicit
  initial certified full pin. Its authenticated read and serialized durable CAS
  address a fixed realm/store identity, protocol version and owner identity;
  compare the **entire** expected 200-byte pin. Persist an incrementing host
  fencing epoch with the pin. An authenticated caller presents a current fenced
  writer grant; no local file, network-supplied key, parsed pin or certificate
  can issue one. Reject stale grants, absent state, wrong identity, conflicting
  same-generation pins, generation overflow and non-successor generations.
  Same-policy transitions require higher height; the host does not infer ledger
  ancestry from a height or hash. Rotation and re-provisioning are separate,
  expressly authorized protocols. A read returns the host's durable latest pin,
  not a client cache; a successful CAS response means the pin survived a host
  restart under the host's durability contract. Authenticate and scope the
  transport; never put owner secrets in certificate or bundle bytes.
- Under a fenced local writer lock, re-read witness and local pin. Require exact
  agreement, then verify the candidate with `PreparedCommit` against that
  predecessor, including its certified ancestry. Durably retain bounded,
  immutable candidate bundle **and** a predecessor/target intent that can be
  revalidated after restart. Sync their names and contents; fail closed at
  capacity rather than deleting older acknowledged data. CAS and sync the local
  full pin; only then request host CAS from exact predecessor to target. Do not
  send the host CAS based on a merely visible local write. Keep the writer fence
  through the final local durability check and acknowledgement. A healthy
  caller acknowledges only after both pins and the exact verified bundle are
  durable and the witness still identifies that target; a later concurrent
  advance makes this attempt's acknowledgement indeterminate, not a rollback.
- Any timeout, lost acknowledgement or crash is **unknown**, never an abort.
  On restart obtain a *fresh authenticated* host pin and exclusive writer fence;
  re-read durable local pin and reverify the exact retained bundle/intent. If
  local pin is target and host still predecessor, repeat host CAS, not local
  rollback. If both equal target, idempotently confirm durable local bytes and
  return its acknowledgement. If both still equal predecessor, a staged but
  uncommitted intent may be retried as a new local publication. Any other pair
  (including an ahead witness, an unrelated winner or a locally rolled-back
  pin) refuses until a separately verified exact restoration or explicit
  conflict decision. The witness is **not** a backup of snapshot/certificate
  bytes and cannot reconstruct them. Host outage, missing intent or payload,
  changed trust, corrupt bytes and revoked custody all fence the protected path;
  never dispatch to legacy `load` or scan older bundles as a workaround.

**Safety under the model assumptions:** after a successful acknowledgement,
local certified bytes and the host's durable pin both reached the target. The
host never accepts a lower generation, different full pin at the same generation,
or a CAS from an old predecessor, so later permitted transitions cannot erase
that *witnessed frontier*. A crash discards only visible, un-synced data; lost
responses do not roll back durable CAS. If all local payloads are lost after an
ack, recovery **refuses** until exact certified data is independently restored;
this is not a guarantee of data availability or proof of host durability. A
client compromising the host, its authority, both trust domains or the signing
quorum, or a host that lies about sync, violates the assumptions. Liveness under
partitions is intentionally not promised. Read snapshots can become stale after
capture; latest-at-completion needs a fenced read or a second host check.

The older fault model uses genuine `PreparedCommit` pins but an in-memory marker in
place of the actual durable journal and bundle verifier. The new file-backed
`protected_file` test instead persists exact bundle and 435-byte canonical intent
bytes and reopens the directory before independent certificate/history checks.
Together they exercise cuts before and after journal/local/witness sync, lost
responses, competing certified pins, invalid/stale grants, witness
outages and coordinated rollback of all local bytes. It does **not** prove a network authentication scheme, OS lock/lease
continuity, backend linearizability, physical power-loss sync, service custody
or cross-machine availability. The prototype adapter assumes a
pre-provisioned certified pin in both stores, retains exactly one intent, refuses another advance while it exists, and provides
no protected bootstrap or intent-retention/compaction protocol. The independent
witness is only a test double; authentication, owner identity, exclusive grant
custody, actual host durability, and physical faults remain unqualified. Never
activate protected write or recovery based on these tests.

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
cargo test --manifest-path prototypes/checkpoint-ledger/Cargo.toml --locked --test rotation
cargo test --manifest-path prototypes/checkpoint-ledger/Cargo.toml --locked --test protected_commit_model
cargo clippy --manifest-path prototypes/checkpoint-ledger/Cargo.toml --all-targets --locked -- -D warnings
cargo check --manifest-path prototypes/checkpoint-ledger/Cargo.toml --target wasm32-unknown-unknown --locked
cargo test --manifest-path prototypes/checkpoint-ledger/Cargo.toml --features native-store --locked
cargo test --manifest-path prototypes/checkpoint-ledger/Cargo.toml --features native-store --locked --test protected_file
cargo clippy --manifest-path prototypes/checkpoint-ledger/Cargo.toml --all-targets --features native-store --locked -- -D warnings
```

The example uses public fixed test keys and an in-memory restart. The WASM check
requires that Rust target and proves compilation only, not browser execution.
The feature-enabled suite also writes a newly created private temporary store,
closes it, reopens and verifies certified history, advances the pin, and reopens
again. Fault-model tests distinguish visible and durable data at every commit
step, including failed syncs, lost acknowledgements, and writers racing at CAS.

## Remaining work

Real protected pin freshness (including a monotonic independently controlled
witness and a physically qualified two-store commit), intent rotation,
physical crash qualification, durable trust rotation and conflict retention,
new-epoch genesis, compaction, and network admission remain open. Direct ledger
users must retain certificates separately; the persistence layer bundles them
with each stored snapshot. Neither establishes global agreement, prevents
malicious signers, authenticates each event author, or authorizes host effects.
Untrusted appends can fill or advance the staging history, so production transport
must not expose them without admission policy.

Follow the [promotion gates](../../kb/plans/valhalla-promotion-gates.md) before
moving this composition into the production workspace or the steel thread.
