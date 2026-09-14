# Valhalla room directory experiment

An excluded, `no_std` Rust **sequential reference model** for the shared public
channel directory. It tests the transitions an eventual replicated registry
would have to agree on. It does not implement consensus, persistent storage,
social evidence admission, a wire decoder, or user-facing room commands.

See the [room creation plan](../../kb/plans/valhalla-room-directory.md) for the
accepted namespace choice, security boundaries and remaining implementation.

## What this experiment establishes

- Slugs are immutable canonical ASCII, 1–48 bytes, unique in the modeled
  directory history. Descriptions are bounded to 256 UTF-8 bytes.
- Exact owner permits and actor requests have separate Ed25519 signature
  domains. They bind directory, policy digest, full owner/actor keys, slug,
  description, next slot, price, expiry and nonce. Agents share owner accounting.
- Slot `n` costs `base*n*n`; the owner must have cumulative earned creation
  credits covering all spent slots. Archiving keeps both the slug reservation
  and charges. Exact retries return the original ID without charging again.
- Creation uses the real rolling interval `(now-window, now]`, not resetting
  fixed buckets. Declined requests leave all state unchanged. Time rollback,
  invalid signatures, insufficient credit and capacity exhaustion deny.
- Finalized support is a **privileged test input**. It deduplicates by source
  owner, beneficiary and explicit activity epoch, binds accepted evidence IDs to
  that contribution, and excludes self/ineligible sources. Arrival time cannot
  renew an old award. Evidence authenticity, activity provenance and maturity
  remain the future adapter's responsibility; this model does not prove that
  engagement occurred and must never accept these inputs from an untrusted caller.
- Search is a bounded scan of finalized active manifests, over slug and
  description. ASCII case folding, literal AND terms, exact non-ASCII bytes;
  an empty query intentionally lists a bounded page. Output reports examined
  records, retained records, revision and partial coverage. It is not an index
  over the whole network and never proves that a slug is free.

The explicit partition test demonstrates why independently accepting on two
replicas **fails** shared uniqueness. Only the modeled agreed apply order
serializes both slug allocation and owner spending. Do not deploy two instances
of this code and call them a decentralized registry.

Limits: 4,096 rooms including tombstones, 256 owner accounts and eligible
sources, 8,192 support dedup keys and accepted evidence bindings, 64 search results
and caller-bounded scan work.
Overflow requires a future reviewed retention/checkpoint mechanism; it never
silently evicts history. Policy constants are illustrative, not calibrated.
Policy validation checks the largest marginal price; cumulative spending overflow
is rejected at creation. Only exact creation retries are mutation-free; repeated
archive calls still advance the modeled revision and time.

Full public keys stand in for durable social OwnerId/AgentId plus their current
control history. `Proposal::sign` and `archive_as_owner` use test keys directly;
they are not production key custody. The full 32-byte genesis ID has not been
mapped into the maintained 128-bit `RoomId`. No grant rotation, permit revocation,
description update, status wire record, snapshot codec or crash proof is supplied.

## Verification

```sh
cargo test --manifest-path prototypes/room-registry/Cargo.toml --locked --offline
cargo clippy --manifest-path prototypes/room-registry/Cargo.toml --all-targets --locked --offline -- -D warnings
```

Tests cover two-owner slug conflicts, sibling slot races, exact retries,
signature/domain/scope mutation, price arithmetic, rolling-window boundaries,
support deduplication, archive/name reuse, memory snapshot preservation, text
bounds and generated search/reference-scan agreement. A memory copy is explicitly
not native restart evidence. WASM compilation is a separate check, not runtime
parity or browser participation.
