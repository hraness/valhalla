#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Pure protocol values for vhalla (valhalla).
//!
//! This crate intentionally has no filesystem, process, network, cryptography,
//! model, or browser dependency. It defines bounded input and distinct states;
//! policy and host crates will own authentication and effect authority.

extern crate alloc;

use alloc::vec::Vec;

/// Maximum bytes accepted by the first bounded parser boundary.
pub const MAX_ENVELOPE_BYTES: usize = 64 * 1024;

/// A stable peer identity handle. Cryptographic verification lives elsewhere.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PeerId(pub u128);

/// A realm identifier.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RealmId(pub u128);

/// A room identifier within a realm.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RoomId(pub u128);

/// A protocol event identifier.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EventId(pub u128);

/// A monotonically increasing sender sequence.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Sequence(pub u64);

/// A policy or membership epoch.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Epoch(pub u64);

/// A bounded envelope that has crossed only the byte-size boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UntrustedEnvelope(Vec<u8>);

/// A parse failure at the first trust boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParseError {
    /// The input exceeded [`MAX_ENVELOPE_BYTES`].
    TooLarge {
        /// Number of bytes supplied by the caller.
        actual: usize,
        /// Maximum accepted byte count.
        limit: usize,
    },
}

/// Parse foreign bytes without assigning them meaning or authority.
#[must_use = "handle the parse result"]
pub fn parse_untrusted(raw: &[u8]) -> Result<UntrustedEnvelope, ParseError> {
    if raw.len() > MAX_ENVELOPE_BYTES {
        return Err(ParseError::TooLarge {
            actual: raw.len(),
            limit: MAX_ENVELOPE_BYTES,
        });
    }
    Ok(UntrustedEnvelope(raw.to_vec()))
}

impl UntrustedEnvelope {
    /// Return the original bounded bytes for a later strict decoder.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Content received from a peer. It is deliberately not a command or policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UntrustedContent {
    /// The authenticated transport identity, if one exists at the adapter layer.
    pub author: Option<PeerId>,
    /// Opaque content bytes; interpretation belongs to a later schema boundary.
    pub bytes: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn boundary_accepts_exact_limit_and_rejects_one_byte_over() {
        assert_eq!(
            parse_untrusted(&vec![0; MAX_ENVELOPE_BYTES])
                .unwrap()
                .as_bytes()
                .len(),
            MAX_ENVELOPE_BYTES
        );
        assert_eq!(
            parse_untrusted(&vec![0; MAX_ENVELOPE_BYTES + 1]),
            Err(ParseError::TooLarge {
                actual: MAX_ENVELOPE_BYTES + 1,
                limit: MAX_ENVELOPE_BYTES
            })
        );
    }

    #[test]
    fn bounded_parse_is_deterministic_for_many_lengths() {
        for length in 0..=MAX_ENVELOPE_BYTES + 2 {
            let result = parse_untrusted(&vec![length as u8; length]);
            assert_eq!(result.is_ok(), length <= MAX_ENVELOPE_BYTES);
        }
    }
}
