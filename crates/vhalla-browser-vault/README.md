# Portable encrypted application-key vault

This `no_std + alloc` Rust crate supplies the key-custody foundation for a
browser client. It uses RustCrypto Argon2id and XChaCha20Poly1305 to protect one
32-byte Ed25519 seed with a password. It has no browser APIs, storage, network,
entropy source or implicit identity generation. A WASM build is not proof of
browser storage, renderer security or usable unlock latency.

## API and ownership

- `seal(Zeroizing<[u8; 32]>, password, salt16, nonce24)` consumes the seed and
  returns an `Envelope`. A production adapter must supply OS/browser CSPRNG
  bytes, with a fresh independently generated salt and nonce for every seal.
  No default seeds or fixture keys exist in the production API. The caller
  cannot use successful encryption as proof that supplied entropy was random.
- `Envelope::from_bytes` checks the exact format and public-key encoding only.
  `claimed_public_key` remains unauthenticated until unlock succeeds.
- `unlock(raw, password)` verifies the authentication tag, decrypts the seed
  and checks that its derived public key equals the authenticated header.
  It returns a private `UnlockedIdentity`, with no `Debug`, `Clone`, raw seed
  getter, serialization or generic signing method.
- The unlocked object exposes `public_key`, `sign_social(UnsignedRecord)`,
  `sign_activity(UnsignedEvent)` and
  `countersign_social(PrimarySignedRecord)`. Maintained social types perform
  their signer and typed-record checks. Public activity must have its exact
  unsigned bytes durably reserved before signing; a possibly signed author
  sequence must never be reused after a timeout, crash or policy change.
  The adapter must separately authorize
  the selected owner/agent, exact draft and operation before calling these
  methods. Key possession is not a current grant or a human gesture.

Dropping the identity clears its private `SigningKey` through dalek's zeroize
feature. Seed/decryption buffers, derived AEAD key and the explicit Argon2
scratch allocation have zeroizing owners; the cipher clears its retained key
on drop. This does not promise to erase every compiler/engine copy, prevent
process-memory inspection or provide hardware/nonextractable key isolation.
The borrowed password is not copied or retained by this crate; its owner must
clear password buffers and form fields. Pass the exact UTF-8 bytes without
trimming or normalization. Passwords are bounded to 12–1024 bytes. A length
check cannot ensure a strong password, and the backup permits offline guessing.

## Canonical v1 envelope

There is exactly one 125-byte representation:

| Offset | Length | Value |
| --- | --- | --- |
| 0 | 5 | `VHBV` followed by version byte `01` |
| 5 | 16 | Argon2 salt |
| 21 | 24 | XChaCha20Poly1305 nonce |
| 45 | 32 | Ed25519 public key |
| 77 | 32 | Encrypted seed |
| 109 | 16 | Poly1305 authentication tag |

The complete first 77 bytes are authenticated associated data. Argon2id
version 0x13 uses exactly 19,456 KiB, two passes, one lane and a 32-byte output;
the derived output is the AEAD key. These costs are fixed by envelope version,
not decoded from attacker-controlled parameters. They match the explicit
[RustCrypto Argon2 0.5.3 defaults](https://raw.githubusercontent.com/RustCrypto/password-hashes/argon2-v0.5.3/argon2/src/params.rs).
The 24-byte nonce construction is supplied by
[RustCrypto XChaCha20Poly1305 0.10.1](https://docs.rs/chacha20poly1305/0.10.1/chacha20poly1305/).
Changing parameters or format requires a new reviewed version; existing bytes
must never be silently reinterpreted.

Malformed lengths, trailing bytes, unknown versions and invalid/weak header
keys are rejected before KDF work. Wrong passwords, modified authenticated
fields and decrypted/header key mismatches do not produce an identity. Each
attempt has fixed cost, but repeated attempts still consume resources: the
browser adapter must limit concurrent unlocks and schedule the work without
freezing its renderer. The library does not install a worker or global queue.

## Backup, recovery and browser boundary

Retain the exact encrypted envelope outside browser storage and keep its
password separately. Recovery imports those unchanged bytes and unlocks with
the same password; it recreates the same application public key. Verify that
key against a previously retained trusted identity before using imported data.
The header alone cannot authenticate a backup, and another complete valid
vault can be substituted. No password reset service or recovery bypass exists.
Losing both an unlocked copy and either the only backup or its password loses
this signing identity. This version intentionally exposes no plaintext export.

An identity backup does not restore signed owner/control history, agent grants,
room evidence, public-activity author floors or pending signing reservations,
spent invitations, private reader state or validator votes.
Those require their own consistent backups and replay. Password changes and
vault replacement must preserve the old recoverable copy until a reviewed
adapter has durably stored, reopened and verified the replacement; this crate
does not implement that mutation workflow.

### Separate author-state parts

`backup::AuthorBackupPage` frames one bounded author-state page. Its context
contains the full network/realm/directory/room/author scope and the independently
selected bootstrap pin, a fresh CSPRNG backup ID, exact `u64` page index,
previous plaintext-page SHA-256 digest, final-page flag, and bounded payload.
The storage crate interprets that payload and verifies completeness. There is
no lifetime page count limit, and one encrypted part is at most 131,373 bytes.

`UnlockedIdentity::{encrypt_author_page,decrypt_author_page}` use HKDF-SHA256
0.12.4 with the backup ID as salt and the exact information string
`vhalla/author-state/backup/key/v1` followed by the complete context. The input
is the identity seed, kept inside key custody. XChaCha20Poly1305 uses a fresh
caller-supplied 24-byte CSPRNG nonce for every part. Its associated data is the
complete 285-byte `VHBENC01` header: context, backup ID, page index, predecessor
digest, final flag, nonce and exact payload length. The final 16 bytes are its
authentication tag. Header identity must equal the actually unlocked key.
The private seed and derived output key have zeroizing owners; this does not
promise elimination of all transient library/compiler/engine copies.

These methods neither sign generic bytes nor export a seed. The browser worker
accepts only the typed page protocol. Restoring parts requires possession of
the original encrypted key backup and its password. Altered, mixed, reordered,
truncated or incomplete streams must fail storage validation even if individual
parts authenticate. A final part authenticates one captured local state; it
does **not** prove that a newer signature or backup does not exist elsewhere.
Only one device may author for a room/key at a time. Stop the prior writer and
restore the latest complete backup. A backup from before a later signature can
still be dangerous on an otherwise empty device, and this format cannot detect
coherent rollback or reconcile signatures created by cloned keys.

IndexedDB should store the encrypted envelope, never the plaintext seed or
password. That storage adapter still needs transaction-completion, competing
tab, crash, quota and eviction handling. An unlocked vault in WASM memory is
exposed to a compromised origin/browser/process. Encryption does not prevent
same-origin hostile code from observing password entry or requesting signatures.
It provides no storage rollback protection, owner-policy enforcement, secure
clock or automatic lock on page suspension. Those limitations must remain
visible in the eventual product and tests.

## Verification fixtures

`vectors/v1-envelope.hex` was generated independently using libsodium 1.0.20,
with seed bytes `00..1f`, salt `20..2f`, nonce `30..47`, and the public password
`Valhalla public fixture password v1`. `v1-wrong-public.hex` has a valid AEAD tag
but replaces the header public key with that of seed `[1; 32]` while retaining
the original encrypted seed. It verifies the separate decrypted-key binding.
All fixture material is public and must never be used for a real identity.
`vectors/generate.py /absolute/path/to/libsodium` reproduces both lines without
using the Rust implementation, downloading dependencies or writing any files.

Tests compare the full frozen envelope, unlock it, exercise typed signing and
countersigning, reject tampering across each field, and cover password/format
bounds and independent salt, nonce and password changes. They always use the
production KDF costs and a bounded number of derivations. The two compile-fail
examples prevent accidental `Clone` and `Debug` exposure.

`vectors/author-page-v1.hex` independently freezes the complete encrypted
author-page header, HKDF derivation and authentication tag. Its public seed is
`[7; 32]`, backup ID `[3; 32]`, nonce `[4; 24]`, and context bytes `[2; 176]`
with the actual derived key at the author offset. The payload is
`bounded signed author state`. `generate_author_page.py /absolute/path/to/libsodium`
uses libsodium's maintained HKDF-SHA256 and XChaCha implementations to reproduce
it without Rust or handwritten cryptographic algorithms. Fixture keys are public.

After workspace integration, validation includes focused native tests/Clippy
and `wasm32-unknown-unknown` compilation. Actual browser execution and platform
ciphertext persistence remain separate gates.

## Optional private storage custody

The `private-storage` feature adds
`UnlockedIdentity::private_storage_key(Context) -> Result<StorageKey, vhalla_private_kernel::Error>`.
The shared kernel HKDF checks the exact authenticated account and full
room/anchor/account/device. It returns an opaque zeroizing StorageKey, never
seed bytes. This separate feature deliberately enables the kernel; existing
`private-rooms` signing remains protocol-only and defaults remain unchanged.

Keep identity, derived custody and private kernels inside the same worker. A
worker command must not return derived keys or raw provider state to Window.
Lock, identity switch and timeout must terminate the whole custody session:
merely dropping this identity does not erase a key already retained by a kernel.

Re-encrypting the same account under another password preserves derived access.
An account-key change does not. The key envelope is still only an account backup,
not a complete private-state backup or permission to restart a previous device.
No state import, device handoff, rollback detection or clone prevention is added.
The production worker/UI is not activated by these library methods.
