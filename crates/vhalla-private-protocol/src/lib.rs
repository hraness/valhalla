#![no_std]
#![forbid(unsafe_code)]

//! Canonical, strictly signed private-room records, separate from public activity.
//!
//! **Verified means signature and format only.** Callers must independently pin
//! the room anchor, authorize account/device roles against current retained state,
//! inspect real MLS credentials/proposals, check a trusted clock, consume grants
//! once, preserve control forks, and commit state/output atomically. This crate
//! performs none of those stateful operations and contains no MLS secret state,
//! transport, generic host signer, or implicit key recovery.
//!
//! Enrollment binds an account to a device; it is not room membership. The v1
//! anchor fixes RFC 9420 suite 0x0001 and owner-device-controlled membership. All
//! room-specific records use a full random room identifier and exact signed anchor
//! digest, never public directory IDs or truncated legacy pairing IDs.
//!
//! A decoded record cannot manufacture the signature-verified wrapper:
//! ```compile_fail
//! use vhalla_private_protocol::{SignedInvitation, VerifiedInvitation};
//! let parsed = SignedInvitation::decode(&[]).unwrap();
//! let forged = VerifiedInvitation(parsed);
//! ```

extern crate alloc;

mod records;
pub use records::*;

use alloc::boxed::Box;
use alloc::vec::Vec;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

/// Maximum complete signed record; checked before parsing or allocation.
pub const MAX_RECORD_BYTES: usize = 4096;
/// Maximum exact MLS artifact bytes accepted by a digest constructor.
pub const MAX_ARTIFACT_BYTES: usize = 128 * 1024;
/// Maximum total additions and removals in one membership control.
pub const MAX_CHANGES: usize = 16;
/// Standard RFC 9420 X25519/AES128GCM/SHA256/Ed25519 suite.
pub const CIPHERSUITE: u16 = 0x0001;
/// Version-one owner-device-controlled membership policy.
pub const MEMBERSHIP_POLICY: u8 = 1;
const PREFIX: &[u8; 5] = b"VHPR\x01";
const SIGN_DOMAIN: &[u8] = b"vhalla/private-room/signature/v1\0";

/// Structural or cryptographic refusal; no state is changed by these errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Fixed byte/count budget exceeded or an artifact is empty.
    Bounds,
    /// Truncated, trailing, noncanonical or inconsistent fields.
    Encoding,
    /// Unsupported record version, type, suite or policy.
    Protocol,
    /// Invalid or weak Ed25519 key.
    Key,
    /// A full identifier or nonce uses the forbidden zero sentinel.
    Identifier,
    /// The typed signer does not match the claimed key.
    Signer,
    /// Strict Ed25519 verification failed.
    Signature,
    /// Invalid validity interval or time outside its half-open interval.
    Time,
    /// Invalid sequence/predecessor shape or overflowing epoch successor.
    Sequence,
    /// Unsorted, duplicate, overlapping or inconsistent membership delta.
    Membership,
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl core::error::Error for Error {}

/// A strictly parsed, non-weak full Ed25519 public key, without role authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Key([u8; 32]);
impl Key {
    /// Parse a full public key. No account or device role is inferred.
    pub fn from_bytes(raw: [u8; 32]) -> Result<Self, Error> {
        let key = VerifyingKey::from_bytes(&raw).map_err(|_| Error::Key)?;
        if key.is_weak() {
            return Err(Error::Key);
        }
        Ok(Self(raw))
    }
    /// Borrow the exact encoded public key.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

macro_rules! identifier {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
        pub struct $name([u8; 32]);
        impl $name {
            /// Parse a full nonzero identifier; parsing does not authenticate it.
            pub fn from_bytes(raw: [u8; 32]) -> Result<Self, Error> {
                if raw == [0; 32] {
                    return Err(Error::Identifier);
                }
                Ok(Self(raw))
            }
            /// Borrow all identifier bytes.
            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }
    };
}
identifier!(
    RoomId,
    "Full private random room ID, independent of public room identifiers."
);
identifier!(
    AnchorId,
    "Commitment to an exact signed room anchor, not a trust decision."
);
identifier!(
    EnrollmentId,
    "Commitment to an exact signed account/device enrollment."
);
identifier!(
    InvitationId,
    "Commitment to an exact signed owner-device invitation."
);
identifier!(ControlId, "Commitment to an exact signed owner control.");
identifier!(
    SuccessionId,
    "Commitment to an exact signed account-authorized owner succession grant."
);
identifier!(
    Nonce,
    "Full nonzero invitation nonce; the caller supplies CSPRNG entropy."
);
identifier!(
    KeyPackageDigest,
    "Domain-separated exact KeyPackage bytes; not MLS validation."
);
identifier!(
    CommitDigest,
    "Domain-separated exact Commit bytes; not MLS validation."
);
identifier!(
    WelcomeDigest,
    "Domain-separated exact Welcome bytes; not MLS validation."
);

fn hash(domain: &[u8], raw: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(domain);
    h.update(raw);
    h.finalize().into()
}
macro_rules! artifact_digest {
    ($name:ident, $domain:literal) => {
        impl $name {
            /// Hash bounded exact nonempty bytes. Does not parse or verify MLS.
            pub fn of_bytes(raw: &[u8]) -> Result<Self, Error> {
                if raw.is_empty() || raw.len() > MAX_ARTIFACT_BYTES {
                    return Err(Error::Bounds);
                }
                Self::from_bytes(hash($domain, raw))
            }
            /// Check exact artifact equality without granting MLS validity.
            pub fn matches(&self, raw: &[u8]) -> Result<bool, Error> {
                Ok(*self == Self::of_bytes(raw)?)
            }
        }
    };
}
artifact_digest!(KeyPackageDigest, b"vhalla/private-room/key-package/v1\0");
artifact_digest!(CommitDigest, b"vhalla/private-room/commit/v1\0");
artifact_digest!(WelcomeDigest, b"vhalla/private-room/welcome/v1\0");

/// Full private-room context. Constructing it does not establish a trusted anchor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrivateRoomScope {
    /// Independent full room ID used by the private protocol.
    pub room: RoomId,
    /// Full exact signed anchor commitment, independently selected by the caller.
    pub anchor: AnchorId,
}

/// Explicit half-open validity interval; no defaults or trusted clock are invented.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Validity {
    not_before: u64,
    expires_at: u64,
}
impl Validity {
    /// Construct an interval with a strictly later expiration.
    pub fn new(not_before: u64, expires_at: u64) -> Result<Self, Error> {
        if not_before >= expires_at {
            return Err(Error::Time);
        }
        Ok(Self {
            not_before,
            expires_at,
        })
    }
    /// First accepted caller-clock second.
    pub const fn not_before(&self) -> u64 {
        self.not_before
    }
    /// First refused caller-clock second.
    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }
    /// Check a caller-supplied clock. Signatures do not make that clock trustworthy.
    pub fn check_at(&self, now: u64) -> Result<(), Error> {
        if now < self.not_before || now >= self.expires_at {
            return Err(Error::Time);
        }
        Ok(())
    }
}

/// Exact claimed control predecessor; no membership or currentness is inferred.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControlFloor {
    sequence: u64,
    id: Option<ControlId>,
}
impl ControlFloor {
    /// Genesis is sequence zero with no ID; later floors require a full ID.
    pub fn new(sequence: u64, id: Option<ControlId>) -> Result<Self, Error> {
        if (sequence == 0) != id.is_none() {
            return Err(Error::Sequence);
        }
        Ok(Self { sequence, id })
    }
    /// Claimed last accepted sequence.
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }
    /// Exact claimed last control, absent only at genesis.
    pub const fn id(&self) -> Option<ControlId> {
        self.id
    }
    /// Checked next sequence; exhaustion cannot wrap into genesis.
    pub fn next_sequence(&self) -> Result<u64, Error> {
        self.sequence.checked_add(1).ok_or(Error::Sequence)
    }
}

trait Record: Clone + Eq {
    const KIND: u8;
    fn signer(&self) -> Key;
    fn validate(&self) -> Result<(), Error>;
    fn write(&self, out: &mut Vec<u8>);
    fn read(input: &mut Reader<'_>) -> Result<Self, Error>;
}
fn unsigned<C: Record>(claims: &C) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(PREFIX);
    out.push(C::KIND);
    claims.write(&mut out);
    out
}
fn signing_bytes<C: Record>(claims: &C) -> Vec<u8> {
    let mut out = Vec::from(SIGN_DOMAIN);
    out.extend(unsigned(claims));
    out
}
fn decode<C: Record>(raw: &[u8]) -> Result<(C, [u8; 64]), Error> {
    if raw.len() > MAX_RECORD_BYTES {
        return Err(Error::Bounds);
    }
    let mut r = Reader(raw);
    if r.take(5)? != PREFIX || r.byte()? != C::KIND {
        return Err(Error::Protocol);
    }
    let claims = C::read(&mut r)?;
    claims.validate()?;
    let signature = r.array()?;
    if !r.0.is_empty() {
        return Err(Error::Encoding);
    }
    Ok((claims, signature))
}
macro_rules! signed_record {
    ($claims:ident, $unsigned:ident, $signed:ident, $verified:ident, $id:ident, $domain:literal) => {
        /// Frozen typed claims ready for custody signing, with no authorization.
        #[derive(Clone, Debug, Eq, PartialEq)]
        pub struct $unsigned {
            claims: $claims,
        }
        impl $unsigned {
            /// Validate fields and fixed budgets before forming signing bytes.
            pub fn new(claims: $claims) -> Result<Self, Error> {
                claims.validate()?;
                if unsigned(&claims).len() + 64 > MAX_RECORD_BYTES {
                    return Err(Error::Bounds);
                }
                Ok(Self { claims })
            }
            /// Borrow the exact frozen claims.
            pub fn claims(&self) -> &$claims {
                &self.claims
            }
            /// Exact domain-separated bytes for a typed custody implementation.
            pub fn signing_bytes(&self) -> Vec<u8> {
                signing_bytes(&self.claims)
            }
            /// Sign this record only; signer identity must exactly match its claims.
            pub fn sign(&self, key: &SigningKey) -> Result<$signed, Error> {
                if key.verifying_key().as_bytes() != self.claims.signer().as_bytes() {
                    return Err(Error::Signer);
                }
                self.attach(key.sign(&self.signing_bytes()).to_bytes())
            }
            /// Attach and strictly verify a custody signature before returning it.
            pub fn attach(&self, signature: [u8; 64]) -> Result<$signed, Error> {
                let signed = $signed {
                    claims: self.claims.clone(),
                    signature,
                };
                signed.verify()?;
                Ok(signed)
            }
        }
        /// Canonical claims and signature; decode alone does not authenticate them.
        #[derive(Clone, Debug, Eq, PartialEq)]
        pub struct $signed {
            claims: $claims,
            signature: [u8; 64],
        }
        impl $signed {
            /// Strict bounded structural decoder; call verify for attribution.
            pub fn decode(raw: &[u8]) -> Result<Self, Error> {
                let (claims, signature) = decode(raw)?;
                Ok(Self { claims, signature })
            }
            /// Borrow unauthenticated claims, unless this record was verified.
            pub fn claims(&self) -> &$claims {
                &self.claims
            }
            /// Encode exact canonical signed bytes.
            pub fn encode(&self) -> Vec<u8> {
                let mut out = unsigned(&self.claims);
                out.extend(self.signature);
                out
            }
            /// Commitment to exact signed bytes; an ID is not an authority claim.
            pub fn id(&self) -> $id {
                $id(hash($domain, &self.encode()))
            }
            /// Verify strict signature and format, not policy/time/membership.
            pub fn verify(&self) -> Result<$verified, Error> {
                self.claims.validate()?;
                let key = VerifyingKey::from_bytes(self.claims.signer().as_bytes())
                    .map_err(|_| Error::Key)?;
                if key.is_weak() {
                    return Err(Error::Key);
                }
                key.verify_strict(
                    &signing_bytes(&self.claims),
                    &Signature::from_bytes(&self.signature),
                )
                .map_err(|_| Error::Signature)?;
                Ok($verified(self.clone()))
            }
        }
        /// Verified signature/format only; no current owner or membership authority.
        #[derive(Clone, Debug, Eq, PartialEq)]
        pub struct $verified($signed);
        impl $verified {
            /// Borrow attributed claims; caller authorization remains mandatory.
            pub fn claims(&self) -> &$claims {
                &self.0.claims
            }
            /// Borrow the exact authenticated record for durable retention.
            pub fn signed(&self) -> &$signed {
                &self.0
            }
            /// Full signed record ID.
            pub fn id(&self) -> $id {
                self.0.id()
            }
        }
    };
}
pub(crate) use signed_record;

struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8], Error> {
        if len > self.0.len() {
            return Err(Error::Encoding);
        }
        let (head, tail) = self.0.split_at(len);
        self.0 = tail;
        Ok(head)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        self.take(N)?.try_into().map_err(|_| Error::Encoding)
    }
    fn byte(&mut self) -> Result<u8, Error> {
        Ok(self.array::<1>()?[0])
    }
    fn blob(&mut self, limit: usize) -> Result<&'a [u8], Error> {
        let len = u32::from_be_bytes(self.array::<4>()?) as usize;
        if len > limit {
            return Err(Error::Bounds);
        }
        self.take(len)
    }
    fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    fn key(&mut self) -> Result<Key, Error> {
        Key::from_bytes(self.array()?)
    }
    fn scope(&mut self) -> Result<PrivateRoomScope, Error> {
        Ok(PrivateRoomScope {
            room: RoomId::from_bytes(self.array()?)?,
            anchor: AnchorId::from_bytes(self.array()?)?,
        })
    }
    fn validity(&mut self) -> Result<Validity, Error> {
        Validity::new(self.u64()?, self.u64()?)
    }
    fn floor(&mut self) -> Result<ControlFloor, Error> {
        let sequence = self.u64()?;
        let raw = self.array()?;
        let id = if raw == [0; 32] {
            None
        } else {
            Some(ControlId::from_bytes(raw)?)
        };
        ControlFloor::new(sequence, id)
    }
}
fn put_scope(out: &mut Vec<u8>, scope: PrivateRoomScope) {
    out.extend(scope.room.0);
    out.extend(scope.anchor.0);
}
fn put_validity(out: &mut Vec<u8>, validity: Validity) {
    out.extend(validity.not_before.to_be_bytes());
    out.extend(validity.expires_at.to_be_bytes());
}
fn put_floor(out: &mut Vec<u8>, floor: ControlFloor) {
    out.extend(floor.sequence.to_be_bytes());
    out.extend(floor.id.map_or([0; 32], |v| v.0));
}

#[cfg(test)]
mod tests;
