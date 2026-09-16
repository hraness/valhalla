//! Domain-separated SHA-256 digests over canonical encodings.
//!
//! Every digest is `SHA-256(domain || u32 big-endian length || bytes)`. The
//! domain string carries the version, so a v2 encoding never collides with a
//! v1 digest, and the length prefix keeps two concatenated encodings from
//! aliasing one.

use sha2::{Digest, Sha256};

/// Digest domain for an assignment (the candidate programs), the `ProgramHash`.
pub const ASSIGNMENT_DOMAIN: &[u8] = b"vhalla/witness/assignment/v1";
/// Digest domain for a task manifest.
pub const MANIFEST_DOMAIN: &[u8] = b"vhalla/witness/manifest/v1";
/// Digest domain for a final run state.
pub const STATE_DOMAIN: &[u8] = b"vhalla/witness/state/v1";
/// Digest domain for the sequence of case results.
pub const OUTPUT_DOMAIN: &[u8] = b"vhalla/witness/output/v1";
/// Digest domain for a witness receipt.
pub const RECEIPT_DOMAIN: &[u8] = b"vhalla/witness/receipt/v1";

/// `SHA-256(domain || len_u32_be || bytes)`. Every canonical encoding in this
/// crate is bounded far below `u32::MAX` bytes.
#[must_use]
pub fn digest(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    Sha256::new()
        .chain_update(domain)
        .chain_update(len.to_be_bytes())
        .chain_update(bytes)
        .finalize()
        .into()
}

macro_rules! digest_newtype {
    ($(#[$doc:meta])* $name:ident, $domain:ident) => {
        $(#[$doc])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
        pub struct $name(pub [u8; 32]);

        impl $name {
            /// Digest the canonical bytes under this type's domain.
            #[must_use]
            pub fn of(bytes: &[u8]) -> Self {
                Self(digest($domain, bytes))
            }
        }
    };
}

digest_newtype!(
    /// Identity of an assignment: the digest of `codec::encode_assignment`.
    ProgramHash,
    ASSIGNMENT_DOMAIN
);
digest_newtype!(
    /// Identity of a task manifest: the digest of `codec::encode_manifest`.
    ManifestHash,
    MANIFEST_DOMAIN
);
digest_newtype!(
    /// Identity of a final state: the digest of `codec::encode_state`.
    StateHash,
    STATE_DOMAIN
);
digest_newtype!(
    /// Identity of every case result in order: the digest of the output bytes.
    OutputHash,
    OUTPUT_DOMAIN
);
digest_newtype!(
    /// Identity of a receipt: the digest of `WitnessReceipt::encode`.
    ReceiptHash,
    RECEIPT_DOMAIN
);
