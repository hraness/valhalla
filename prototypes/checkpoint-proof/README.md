# vhalla (valhalla): checkpoint certificate reference

This disposable, `no_std` + `alloc` Rust model explores authenticated checkpoint
claims. It remains outside the production workspace. It does not connect peers,
execute host effects, persist state, or implement consensus.

## Boundary

An immutable `TrustConfig` pins a realm, epoch, full Ed25519 public keys, threshold,
signer limit, and proof byte limit. A domain-separated SHA-256 digest of that
configuration is part of every signed statement. Reordering members preserves
the digest; changing membership, threshold, epoch, or limits requires new
signatures. This is an explicit trust configuration, not automatic discovery of
trustworthy members or a Sybil defense.

`verify` checks supported version, lengths, counts, context, configuration digest,
identical statements, distinct known signers, and strict Ed25519 signatures. All
provided approvals must pass, even after reaching the threshold. Weak public
keys are rejected when configuring trust. Signing malformed statements returns
an error. There are at most 128 members, 128 realm bytes, and 64 KiB of modeled
proof bytes; limits are checked before verification allocates or hashes input.
Raw structs are untrusted and may already have been allocated by a caller: a
future wire decoder must enforce those bounds before allocating them.

Only verification constructs `VerifiedProof`. Its fields are private, its views
are immutable, and a compile-fail test protects the mutation boundary. This type
means configured keys signed the claim. It does **not** mean the root was derived
correctly, history is available, the checkpoint is fresh, or an operation is
authorized. There is no dependency from this experiment to policy or host crates.

`ProofObserver` remembers head/root pairs at up to 4,096 distinct heights under
one configuration. Same claim with different approval order/subset is a duplicate;
a different claim at the same retained height is a conflict. Exhaustion fails
closed with no eviction. Conflict/error results leave existing observations
unchanged. The caller retains certificates if it needs attributable evidence;
the observer itself retains only their head/root pairs.

The observer only reports conflicts it sees. It does not validate ancestry across
heights, prevent signers equivocating, survive restart, choose a branch, or
establish finality. A test intentionally constructs two conflicting certificates
that both pass stateless verification. Threshold signatures alone cannot provide
the missing agreement and recovery rules.

## Canonical statements

All integers are unsigned big endian. Byte lengths count UTF-8 bytes with no
Unicode normalization; distinct spellings are distinct realms.

```text
trust digest = SHA-256(
  "valhalla/checkpoint-proof/trust/v1"
  || version:u16 || realm_length:u64 || realm_bytes
  || epoch:u64 || threshold:u64 || max_signers:u64 || max_proof_bytes:u64
  || member_count:u64 || sorted_full_public_keys:32*N
)

signed transcript =
  "valhalla/checkpoint-proof/statement/v1"
  || version:u16 || realm_length:u64 || realm_bytes || epoch:u64
  || trust_digest:32 || head:32 || state_root:32 || height:u64
```

Version 1 is the only accepted version. Approval ordering does not affect the
verification result. There is no canonical serialized certificate or raw byte
decoder yet. `encoded_len` accounts for the proposed proof domain, outer
statement, u64 count, and repeated statement/key/signature records; it is an
admission budget for this in-memory model, not a shipped wire format.

The independent transcript fixture is 161 bytes with SHA-256
`54b51ba9f2b1c2e554676d410f95869528969e218bf171e915dca59b7b6b45ed`.
Regenerate with Python's standard library:

```python
import hashlib, struct
raw = (b"valhalla/checkpoint-proof/statement/v1"
       + struct.pack(">HQ", 1, 1) + b"r" + struct.pack(">Q", 7)
       + bytes([3]) * 32 + bytes([1]) * 32 + bytes([2]) * 32
       + struct.pack(">Q", 4))
assert len(raw) == 161
print(hashlib.sha256(raw).hexdigest())
```

## Verify and promote

```console
cargo test --manifest-path prototypes/checkpoint-proof/Cargo.toml --locked
cargo clippy --manifest-path prototypes/checkpoint-proof/Cargo.toml --all-targets --locked -- -D warnings
cargo check --manifest-path prototypes/checkpoint-proof/Cargo.toml --target wasm32-unknown-unknown --locked
```

Tests cover threshold/subset ordering, duplicate/unknown signers, invalid extra
approvals, weak keys, bounds, trust reconfiguration, conflicting certificates,
observer capacity, an independent transcript vector, generated field tampering,
and distinct statement encodings. WASM compilation checks portability only;
browser execution and byte-for-byte cross-target vectors remain future evidence.

Promotion requires a reviewed bounded decoder, explicit production realm-ID
mapping, independently derived ledger roots and ancestry checks, durable trust
and conflict records, and restart/rollback resistance. Follow the
[promotion gates](../../kb/plans/valhalla-promotion-gates.md). A certificate must
remain evidence consumed by local policy, never a constructor for host authority.
