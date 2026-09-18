# Valhalla native identity

Experimental Unix custody for one application signing key. It supports the
application keys used by the `vhalla` CLI. The optional
[native adapter](../vhalla-native/README.md) connects them to loopback chat.

```console
cargo run -p vhalla-cli --locked -- identity init ./my-agent
cargo run -p vhalla-cli --locked -- identity show ./my-agent
```

`init` requires a new directory and prints only the full application public key.
`show` opens an existing identity and prints the same public key. Neither command
joins a network or replaces an existing key. No global installation or `vh`
alias is performed by these examples.

The directory is mode 0700; its key record and lifetime lock are mode 0600.
Create uses OS entropy, writes a fixed 72-byte versioned record, synchronizes
contents, publishes without replacing another name, and synchronizes directories
before returning success. The key record contains a corruption checksum, not an
authentication tag. Secret buffers and the retained Ed25519 key use zeroization;
the API has no seed getter, Clone or Debug implementation.

Open checks type, permissions, exact size, link count, record checksum and the
exclusive process lock. Unknown entries and interrupted temporary files fail
closed. It does not delete, repair or regenerate identity data. If creation
reports an I/O failure, its result may be uncertain: inspect the owned directory
and explicitly open a complete record. Never retry by deleting that directory.

**This is private-file custody, not encrypted storage or protection against a
compromised owner/root.** The directory and ancestors must stay owner-controlled.
Path checks do not defend against a hostile process racing filesystem changes.
Ordinary files cannot detect adversarial disk rollback. Physical power-loss
qualification, recovery tooling, independent security review and non-Unix
backends remain open. `File::try_lock` requires Rust 1.89 or newer; tests currently
run on 1.97.1 locally and the CI stable toolchain.

The application identity is persisted separately from transport configuration.
This slice does not store or export a transport secret. Actual transport key
custody remains an adapter decision; every session binds the authenticated
transport keys observed on that connection to the persistent application keys.

The library can initiate/respond/confirm a paired session while retaining its
secret key and obtaining each nonce from OS entropy. It signs outbound envelopes
using a borrowed key. The joined test reopens an identity, establishes a fresh
session, rejects recorded handshake/chat traffic and accepts a new message.
This is native filesystem plus in-memory session evidence, not a network or
process-crash test.

```console
cargo test -p vhalla-identity --locked
cargo clippy -p vhalla-identity --all-targets --locked -- -D warnings
```

Tests cover private creation/reopen, distinct generated keys, signed message
verification, exclusive opens, corrupt/partial records, interrupted
publication, symlinks/hardlinks, exposed permissions and generated record mutations.

## BIP39 backup and restore

The CLI can encode the 32-byte Ed25519 seed as a 24-word English BIP39
mnemonic and restore the same key from that phrase:

```console
vhalla identity init ./my-agent
vhalla identity backup ./my-agent > my-agent.backup

# The first two lines are the mnemonic and the application public key.
cat my-agent.backup

# If the original directory is ever lost, create a new one from the phrase:
vhalla identity restore ./my-agent-restored < my-agent.backup
vhalla identity show ./my-agent-restored
```

`backup` only opens the identity and prints the phrase plus public key; it does
not write a file. Operators should write the mnemonic to durable offline storage
and keep the public key in a separate convenient place. `restore` reads the
mnemonic from stdin so the phrase never appears in shell history or process
arguments. It validates the BIP39 checksum, rejects any phrase that does not
decode to exactly 32 bytes of entropy, and creates a new private directory with
the same record format as `init`. The restored `application-key` is byte-for-byte
identical to the lost one — the mnemonic is the only recoverable secret; if it
is lost, the identity is gone.

The command entry point and CLI lifecycle tests live in `vhalla-cli`; the identity
library has no transport dependency. `cargo test -p vhalla-cli --locked` checks the
default identity commands.
