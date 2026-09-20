#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Signed, bounded route hints for public non-validator peers.
//!
//! An advertisement proves only that an application key signed these claims.
//! It grants no validator admission, room membership, posting rights or host
//! authority. Network identity must come from an independent trusted source.
//! This crate has no networking, DNS, entropy, clock, storage or background work.

extern crate alloc;

pub mod activity;
pub mod discovery;
pub mod response;

mod endpoint;
pub use endpoint::{Endpoint, Host, Scheme, API_BASE, MAX_ENDPOINT_BYTES};

use alloc::vec::Vec;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

const MAGIC: &[u8; 5] = b"VHPA\x01";
const DOMAIN: &[u8] = b"vhalla/public-peer-advertisement/v1\0";
const FIXED_BYTES: usize = 5 + 32 + 32 + 8 + 8 + 8 + 2 + 4 + 1 + 64;
/// Maximum routes in one advertisement.
pub const MAX_ENDPOINTS: usize = 4;
/// Exact version-1 upper wire bound, checked before parsing or allocation.
pub const MAX_ADVERTISEMENT_BYTES: usize = FIXED_BYTES + MAX_ENDPOINTS * (2 + MAX_ENDPOINT_BYTES);
/// The only application protocol version understood by this codec.
pub const PROTOCOL_VERSION: u16 = 1;
/// Hard maximum signed lifetime, in Unix seconds.
pub const MAX_TTL_SECONDS: u64 = 24 * 60 * 60;
/// Hard maximum policy allowance for a future issuer clock, in seconds.
pub const MAX_CLOCK_SKEW_SECONDS: u64 = 5 * 60;

/// A bounded rejection at the public advertisement boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// A byte, count or allocation ceiling was exceeded.
    Bounds,
    /// Invalid canonical framing, key lengths, or trailing data.
    Encoding,
    /// Unknown envelope/application protocol version or capability.
    Protocol,
    /// A route is noncanonical or outside the conservative public route policy.
    Endpoint,
    /// Endpoints are duplicated or not in strictly increasing byte order.
    EndpointOrder,
    /// Invalid or weak application public key.
    Key,
    /// The signing key does not match the claimed application key.
    Signer,
    /// Strict domain-separated signature verification failed.
    Signature,
    /// Network scope is zero or differs from the independently trusted network.
    Network,
    /// Sequence is zero, repeated or older than retained evidence.
    Sequence,
    /// The retained sequence evidence belongs to a different application key.
    Peer,
    /// The exclusive expiration boundary has been reached.
    Expired,
    /// Issuance is beyond the caller's allowed future clock skew.
    IssuedInFuture,
    /// Signed lifetime is inverted, zero or exceeds an applicable TTL.
    Lifetime,
    /// The caller supplied an invalid verification policy.
    Policy,
}

/// Advertised service features, not authorization or proof of availability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Capabilities(u32);

impl Capabilities {
    /// Claims a bounded signed-evidence read service.
    pub const READ: Self = Self(1);
    /// Claims a signed-record submission service.
    pub const PUBLISH: Self = Self(2);
    /// Claims a live activity subscription service.
    pub const SUBSCRIBE: Self = Self(4);

    /// Check a nonempty version-1 capability set; unknown bits fail closed.
    pub fn from_bits(bits: u32) -> Result<Self, Error> {
        if bits == 0 || bits & !7 != 0 {
            return Err(Error::Protocol);
        }
        Ok(Self(bits))
    }

    /// Return the canonical wire bits.
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Whether every requested claim appears in this set.
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

/// Proposed descriptor content. Constructing claims establishes no evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdvertisementClaims {
    /// Full independently chosen network identifier; zero is not a network.
    pub network: [u8; 32],
    /// Full Ed25519 application key; not a validator or transport key.
    pub application_key: [u8; 32],
    /// Strictly increasing issuer sequence within this network and full key.
    pub sequence: u64,
    /// Issuance Unix seconds according to the issuer.
    pub issued_at: u64,
    /// Exclusive expiry Unix seconds.
    pub expires_at: u64,
    /// Application protocol version; version 1 only in this codec.
    pub protocol: u16,
    /// Claimed services, with no grant or availability implication.
    pub capabilities: Capabilities,
    /// One to four canonical URLs, strictly sorted by their ASCII bytes.
    pub endpoints: Vec<Endpoint>,
}

/// Immutable checked content ready for native or asynchronous external signing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnsignedAdvertisement {
    claims: AdvertisementClaims,
}

impl UnsignedAdvertisement {
    /// Check bounded content without sorting or silently normalizing it.
    pub fn new(claims: AdvertisementClaims) -> Result<Self, Error> {
        check_claims(&claims)?;
        Ok(Self { claims })
    }

    /// Exact domain-separated message for an external Ed25519 signing provider.
    pub fn signing_bytes(&self) -> Vec<u8> {
        transcript(&self.claims)
    }

    /// Attach and strictly verify a detached signature over signing_bytes().
    ///
    /// This authenticates content only; call PeerAdvertisement::verify for the
    /// independently trusted network, current time and monotone sequence check.
    pub fn attach_signature(self, signature: [u8; 64]) -> Result<PeerAdvertisement, Error> {
        let advertisement = PeerAdvertisement {
            claims: self.claims,
            signature,
        };
        advertisement.check_signature()?;
        Ok(advertisement)
    }

    /// Sign using a matching locally held application key. No I/O occurs.
    pub fn sign_with_key(self, key: &SigningKey) -> Result<PeerAdvertisement, Error> {
        if key.verifying_key().to_bytes() != self.claims.application_key {
            return Err(Error::Signer);
        }
        let signature = key.sign(&self.signing_bytes()).to_bytes();
        self.attach_signature(signature)
    }
}

/// Canonically decoded signed claims; the signature and freshness are untrusted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerAdvertisement {
    claims: AdvertisementClaims,
    signature: [u8; 64],
}

impl PeerAdvertisement {
    /// Decode one bounded, canonical version-1 frame without trusting its signer.
    pub fn decode(raw: &[u8]) -> Result<Self, Error> {
        if raw.len() > MAX_ADVERTISEMENT_BYTES {
            return Err(Error::Bounds);
        }
        if raw.len() < FIXED_BYTES || raw.get(..4) != Some(&MAGIC[..4]) {
            return Err(Error::Encoding);
        }
        if raw[4] != MAGIC[4] {
            return Err(Error::Protocol);
        }
        let mut input = Reader(&raw[5..]);
        let network = input.array()?;
        let application_key = input.array()?;
        let sequence = u64::from_be_bytes(input.array()?);
        let issued_at = u64::from_be_bytes(input.array()?);
        let expires_at = u64::from_be_bytes(input.array()?);
        let protocol = u16::from_be_bytes(input.array()?);
        let capabilities = Capabilities::from_bits(u32::from_be_bytes(input.array()?))?;
        let count = usize::from(input.array::<1>()?[0]);
        if count == 0 || count > MAX_ENDPOINTS {
            return Err(Error::Bounds);
        }
        let mut endpoints = Vec::with_capacity(count);
        for _ in 0..count {
            let length = usize::from(u16::from_be_bytes(input.array()?));
            if length > MAX_ENDPOINT_BYTES {
                return Err(Error::Bounds);
            }
            let raw_endpoint = input.take(length)?;
            let url = core::str::from_utf8(raw_endpoint).map_err(|_| Error::Endpoint)?;
            endpoints.push(Endpoint::parse(url)?);
        }
        let signature = input.array()?;
        if !input.0.is_empty() {
            return Err(Error::Encoding);
        }
        let claims = AdvertisementClaims {
            network,
            application_key,
            sequence,
            issued_at,
            expires_at,
            protocol,
            capabilities,
            endpoints,
        };
        check_claims(&claims)?;
        Ok(Self { claims, signature })
    }

    /// Encode the exact immutable signed claims; no verification is implied.
    pub fn encode(&self) -> Vec<u8> {
        let mut raw = unsigned_bytes(&self.claims);
        raw.extend_from_slice(&self.signature);
        raw
    }

    /// Borrow explicitly untrusted content from a decoded advertisement.
    pub const fn unverified_claims(&self) -> &AdvertisementClaims {
        &self.claims
    }

    /// Restore an immutable replay floor from retained signed evidence.
    ///
    /// This checks signature and expected network, deliberately not freshness.
    /// Use only for a previously retained descriptor when reopening local state;
    /// the returned value exposes no routes and cannot authorize a connection.
    /// Keeping the signed descriptor lets an expired floor survive a restart.
    pub fn restore_sequence_anchor(&self, network: [u8; 32]) -> Result<SequenceAnchor, Error> {
        if self.claims.network != network {
            return Err(Error::Network);
        }
        self.check_signature()?;
        Ok(SequenceAnchor::from_claims(&self.claims))
    }

    /// Check signature, independently trusted scope, time policy and sequence.
    ///
    /// Retain the greatest verified descriptor for each (network, full key)
    /// and supply its sequence anchor as previous when replacing it. Expiration must not erase
    /// that sequence floor. None is only for a key with no retained history.
    /// Equal sequences are rejected, even for byte-identical replay.
    ///
    /// The caller bounds both total peers and signature attempts before calling
    /// this function. A caller-supplied nondecreasing clock and durable sequence
    /// retention are necessary for rollback/replay protection across restarts.
    pub fn verify(
        &self,
        policy: &VerificationPolicy,
        previous: Option<&SequenceAnchor>,
    ) -> Result<VerifiedAdvertisement, Error> {
        policy.check()?;
        let claims = &self.claims;
        if claims.network != policy.network {
            return Err(Error::Network);
        }
        if claims.expires_at <= policy.now {
            return Err(Error::Expired);
        }
        if claims.issued_at > policy.now.saturating_add(policy.max_clock_skew_seconds) {
            return Err(Error::IssuedInFuture);
        }
        if claims.expires_at - claims.issued_at > policy.max_ttl_seconds {
            return Err(Error::Lifetime);
        }
        if let Some(previous) = previous {
            let retained = previous;
            if retained.network != claims.network {
                return Err(Error::Network);
            }
            if retained.application_key != claims.application_key {
                return Err(Error::Peer);
            }
            if claims.sequence <= retained.sequence {
                return Err(Error::Sequence);
            }
        }
        self.check_signature()?;
        Ok(VerifiedAdvertisement {
            advertisement: self.clone(),
            verified_at: policy.now,
        })
    }

    fn check_signature(&self) -> Result<(), Error> {
        checked_key(&self.claims.application_key)?
            .verify_strict(
                &transcript(&self.claims),
                &Signature::from_bytes(&self.signature),
            )
            .map_err(|_| Error::Signature)
    }
}

/// Immutable network/key/sequence evidence used only as a replay floor.
///
/// It carries no endpoint and proves neither freshness nor membership. Retain
/// the corresponding signed advertisement to reconstruct this floor after a
/// restart with PeerAdvertisement::restore_sequence_anchor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SequenceAnchor {
    network: [u8; 32],
    application_key: [u8; 32],
    sequence: u64,
}

impl SequenceAnchor {
    fn from_claims(claims: &AdvertisementClaims) -> Self {
        Self {
            network: claims.network,
            application_key: claims.application_key,
            sequence: claims.sequence,
        }
    }

    /// Full network scope of this retained sequence.
    pub const fn network(&self) -> &[u8; 32] {
        &self.network
    }

    /// Full application identity whose sequence this anchors.
    pub const fn application_key(&self) -> &[u8; 32] {
        &self.application_key
    }

    /// Greatest retained issuer sequence, never an implicit membership epoch.
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }
}

/// Trusted caller policy, never taken from a received advertisement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerificationPolicy {
    /// Independently pinned network identifier.
    pub network: [u8; 32],
    /// Caller clock in Unix seconds; the caller detects clock rollback.
    pub now: u64,
    /// Allowed future issuance skew, at most MAX_CLOCK_SKEW_SECONDS.
    pub max_clock_skew_seconds: u64,
    /// Maximum signed lifetime, nonzero and at most MAX_TTL_SECONDS.
    pub max_ttl_seconds: u64,
}

impl VerificationPolicy {
    fn check(&self) -> Result<(), Error> {
        if self.network == [0; 32]
            || self.max_ttl_seconds == 0
            || self.max_ttl_seconds > MAX_TTL_SECONDS
            || self.max_clock_skew_seconds > MAX_CLOCK_SKEW_SECONDS
        {
            return Err(Error::Policy);
        }
        Ok(())
    }
}

/// Immutable verified route claims, fresh only at verified_at().
///
/// No conversion to authority, validator membership or room admission exists.
/// Recheck freshness before later use; cached evidence does not stay current.
///
/// ```compile_fail
/// use vhalla_public_protocol::{PeerAdvertisement, VerifiedAdvertisement};
/// fn skip(raw: PeerAdvertisement) -> VerifiedAdvertisement { raw.into() }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedAdvertisement {
    advertisement: PeerAdvertisement,
    verified_at: u64,
}

impl VerifiedAdvertisement {
    /// Borrow authenticated immutable content, not an authority grant.
    pub const fn claims(&self) -> &AdvertisementClaims {
        &self.advertisement.claims
    }

    /// Time at which the supplied policy admitted this evidence.
    pub const fn verified_at(&self) -> u64 {
        self.verified_at
    }

    /// Obtain the scoped replay floor to retain even after this route expires.
    pub fn sequence_anchor(&self) -> SequenceAnchor {
        SequenceAnchor::from_claims(self.claims())
    }

    /// Re-emit signed evidence for storage or transport.
    pub fn encode(&self) -> Vec<u8> {
        self.advertisement.encode()
    }
}

fn checked_key(bytes: &[u8; 32]) -> Result<VerifyingKey, Error> {
    let key = VerifyingKey::from_bytes(bytes).map_err(|_| Error::Key)?;
    if key.is_weak() {
        return Err(Error::Key);
    }
    Ok(key)
}

fn check_claims(claims: &AdvertisementClaims) -> Result<(), Error> {
    if claims.network == [0; 32] {
        return Err(Error::Network);
    }
    checked_key(&claims.application_key)?;
    if claims.sequence == 0 {
        return Err(Error::Sequence);
    }
    if claims.protocol != PROTOCOL_VERSION {
        return Err(Error::Protocol);
    }
    let ttl = claims
        .expires_at
        .checked_sub(claims.issued_at)
        .ok_or(Error::Lifetime)?;
    if ttl == 0 || ttl > MAX_TTL_SECONDS {
        return Err(Error::Lifetime);
    }
    if claims.endpoints.is_empty() || claims.endpoints.len() > MAX_ENDPOINTS {
        return Err(Error::Bounds);
    }
    if claims
        .endpoints
        .windows(2)
        .any(|pair| pair[0].as_str() >= pair[1].as_str())
    {
        return Err(Error::EndpointOrder);
    }
    Ok(())
}

fn unsigned_bytes(claims: &AdvertisementClaims) -> Vec<u8> {
    let mut raw = Vec::with_capacity(MAX_ADVERTISEMENT_BYTES - 64);
    raw.extend_from_slice(MAGIC);
    raw.extend_from_slice(&claims.network);
    raw.extend_from_slice(&claims.application_key);
    raw.extend_from_slice(&claims.sequence.to_be_bytes());
    raw.extend_from_slice(&claims.issued_at.to_be_bytes());
    raw.extend_from_slice(&claims.expires_at.to_be_bytes());
    raw.extend_from_slice(&claims.protocol.to_be_bytes());
    raw.extend_from_slice(&claims.capabilities.bits().to_be_bytes());
    raw.push(claims.endpoints.len() as u8);
    for endpoint in &claims.endpoints {
        raw.extend_from_slice(&(endpoint.as_str().len() as u16).to_be_bytes());
        raw.extend_from_slice(endpoint.as_str().as_bytes());
    }
    raw
}

fn transcript(claims: &AdvertisementClaims) -> Vec<u8> {
    let mut message = Vec::with_capacity(DOMAIN.len() + MAX_ADVERTISEMENT_BYTES - 64);
    message.extend_from_slice(DOMAIN);
    message.extend_from_slice(&unsigned_bytes(claims));
    message
}

struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, size: usize) -> Result<&'a [u8], Error> {
        let bytes = self.0.get(..size).ok_or(Error::Encoding)?;
        self.0 = &self.0[size..];
        Ok(bytes)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        self.take(N)?.try_into().map_err(|_| Error::Encoding)
    }
}

#[cfg(test)]
mod tests;
