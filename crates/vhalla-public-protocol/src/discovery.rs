//! Bounded public route discovery, with no validator or room authority.
//!
//! The receiving peer proves its responses; every listed advertisement must
//! also be independently verified. A registry may omit peers or exhaust its
//! capacity. Hashcash is a hardware-biased admission cost, not Sybil resistance.
use crate::response::{hex, MAX_REQUEST_TARGET};
use crate::{
    PeerAdvertisement, VerificationPolicy, VerifiedAdvertisement, MAX_ADVERTISEMENT_BYTES,
    MAX_CLOCK_SKEW_SECONDS, MAX_TTL_SECONDS,
};
use alloc::{format, string::String, vec::Vec};
use ed25519_dalek::{Signature, Signer, SigningKey};
use sha2::{Digest, Sha256};
use vhalla_botcaptcha::{
    admit::WitnessVerifier,
    challenge::{
        Algorithm, Challenge, ChallengeContext, Difficulty, Purpose, Requirement,
        VerifiedChallenge, CHALLENGE_BYTES,
    },
    hashcash::{HashcashResponse, HASHCASH_RESPONSE_BYTES},
    window::OneUseWindow,
};
use vhalla_core::{RealmId, RoomId};
use vhalla_witness::{hash::ManifestHash, platform::WorkAllowance};

/// Maximum independently signed descriptors returned by one listing.
pub const MAX_PEERS_PER_PAGE: usize = 16;
/// Maximum canonical listing frame.
pub const MAX_PEER_PAGE_BYTES: usize =
    5 + 32 + 8 + 32 + 1 + 1 + MAX_PEERS_PER_PAGE * (2 + MAX_ADVERTISEMENT_BYTES);
/// Signed registration challenge lifetime; expiration is exclusive here.
pub const CHALLENGE_LIFETIME: u64 = 60;
/// Fixed new-key cost: approximately 2^20 hashes in expectation.
pub const NEW_PEER_DIFFICULTY: u8 = 20;
/// Retained-key renewal cost. It cannot be used after the key's floor retires.
pub const KNOWN_PEER_DIFFICULTY: u8 = 1;
/// Hard caller-selected solver budget ceiling, shared by native and WASM users.
pub const MAX_SOLVE_ATTEMPTS: u64 = 1 << 24;
/// Exact challenge wrapper size, including the existing Botcaptcha challenge.
pub const REGISTRATION_CHALLENGE_BYTES: usize = 5 + 32 * 3 + CHALLENGE_BYTES;
/// Registration hard framing bound, checked before allocation.
pub const MAX_REGISTRATION_BYTES: usize =
    5 + REGISTRATION_CHALLENGE_BYTES + 2 + MAX_ADVERTISEMENT_BYTES + HASHCASH_RESPONSE_BYTES;
/// Fixed receipt frame length.
pub const REGISTRATION_RECEIPT_BYTES: usize = 5 + 32 * 3 + 8 * 4;
/// Maximum encoded signed discovery proof.
pub const MAX_DISCOVERY_PROOF_BYTES: usize = 5 + 32 * 3 + 1 + 64 + 32 + 64;
const REQUEST_DOMAIN: &[u8] = b"vhalla/public-discovery/challenge-context/v1\0";
const RESPONSE_DOMAIN: &[u8] = b"vhalla/public-discovery/response/v1\0";

/// A bounded rejection at a discovery protocol boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiscoveryError {
    /// Length, count, timestamp or arithmetic bound exceeded.
    Bounds,
    /// Noncanonical, truncated, duplicate or unsupported framing.
    Encoding,
    /// Full network, key, request or body context differs.
    Scope,
    /// Issuance, expiration or retained clock policy refused the evidence.
    Time,
    /// A key is invalid/weak or a strict signature failed.
    Signature,
    /// Proof of work is insufficient or uses the wrong contract.
    Work,
    /// The explicit solver budget found no nonce.
    Exhausted,
}
type Result<T> = core::result::Result<T, DiscoveryError>;
fn hash(raw: &[u8]) -> [u8; 32] {
    Sha256::digest(raw).into()
}
fn key(raw: &[u8; 32]) -> Result<()> {
    crate::checked_key(raw)
        .map(|_| ())
        .map_err(|_| DiscoveryError::Signature)
}

/// All request semantics are included in the response signature.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiscoveryKind {
    /// First page uses generation=0 and the zero key; continuations use both returned values.
    List {
        /// Exact observed registry generation, or zero to start.
        generation: u64,
        /// Exclusive complete public-key cursor, zero to start.
        after: [u8; 32],
        /// Nonzero requested count, at most MAX_PEERS_PER_PAGE.
        count: u8,
    },
    /// Request work bound to exactly one publisher and signed advertisement.
    Challenge {
        /// Full publishing application key.
        publisher: [u8; 32],
        /// SHA-256 of the exact canonical signed advertisement.
        advertisement: [u8; 32],
    },
    /// Submit exactly one bounded signed registration as the POST body.
    Register {
        /// SHA-256 of the complete canonical registration body.
        registration: [u8; 32],
    },
}
/// Retain this immutable context, including a fresh unpredictable nonce, before sending.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DiscoveryRequest {
    nonce: [u8; 32],
    kind: DiscoveryKind,
}
impl DiscoveryRequest {
    /// Validate the complete bounded request. Entropy is provided by the caller.
    pub fn new(nonce: [u8; 32], kind: DiscoveryKind) -> Result<Self> {
        if nonce == [0; 32] {
            return Err(DiscoveryError::Scope);
        }
        match kind {
            DiscoveryKind::List {
                generation,
                after,
                count,
            } => {
                if count == 0
                    || usize::from(count) > MAX_PEERS_PER_PAGE
                    || (generation == 0 && after != [0; 32])
                {
                    return Err(DiscoveryError::Bounds);
                }
            }
            DiscoveryKind::Challenge {
                publisher,
                advertisement,
            } => {
                key(&publisher)?;
                if advertisement == [0; 32] {
                    return Err(DiscoveryError::Scope);
                }
            }
            DiscoveryKind::Register { registration } => {
                if registration == [0; 32] {
                    return Err(DiscoveryError::Scope);
                }
            }
        }
        Ok(Self { nonce, kind })
    }
    /// Exact caller challenge.
    pub const fn nonce(&self) -> [u8; 32] {
        self.nonce
    }
    /// Complete operation semantics.
    pub const fn kind(&self) -> DiscoveryKind {
        self.kind
    }
    /// Canonical origin-form request target; no arbitrary paths or reordered parameters.
    pub fn target(&self) -> String {
        match self.kind {
            DiscoveryKind::List {
                generation,
                after,
                count,
            } => format!(
                "/vhalla/v1/peers?generation={generation}&after={}&count={count}&nonce={}",
                hex(&after),
                hex(&self.nonce)
            ),
            DiscoveryKind::Challenge {
                publisher,
                advertisement,
            } => format!(
                "/vhalla/v1/peers/challenge?publisher={}&advertisement={}&nonce={}",
                hex(&publisher),
                hex(&advertisement),
                hex(&self.nonce)
            ),
            DiscoveryKind::Register { registration } => format!(
                "/vhalla/v1/peers/register?registration={}&nonce={}",
                hex(&registration),
                hex(&self.nonce)
            ),
        }
    }
    /// Accept only the exact supported canonical HTTP target.
    pub fn parse_target(raw: &str) -> Result<Self> {
        if raw.len() > MAX_REQUEST_TARGET {
            return Err(DiscoveryError::Bounds);
        }
        let req = if let Some(s) = raw.strip_prefix("/vhalla/v1/peers?generation=") {
            let (generation, s) = split(s, "&after=")?;
            let (after, s) = split(s, "&count=")?;
            let (count, nonce) = split(s, "&nonce=")?;
            Self::new(
                unhex(nonce)?,
                DiscoveryKind::List {
                    generation: number(generation)?,
                    after: unhex(after)?,
                    count: u8::try_from(number(count)?).map_err(|_| DiscoveryError::Bounds)?,
                },
            )?
        } else if let Some(s) = raw.strip_prefix("/vhalla/v1/peers/challenge?publisher=") {
            let (publisher, s) = split(s, "&advertisement=")?;
            let (advertisement, nonce) = split(s, "&nonce=")?;
            Self::new(
                unhex(nonce)?,
                DiscoveryKind::Challenge {
                    publisher: unhex(publisher)?,
                    advertisement: unhex(advertisement)?,
                },
            )?
        } else if let Some(s) = raw.strip_prefix("/vhalla/v1/peers/register?registration=") {
            let (registration, nonce) = split(s, "&nonce=")?;
            Self::new(
                unhex(nonce)?,
                DiscoveryKind::Register {
                    registration: unhex(registration)?,
                },
            )?
        } else {
            return Err(DiscoveryError::Encoding);
        };
        if req.target() != raw {
            return Err(DiscoveryError::Encoding);
        }
        Ok(req)
    }
    /// Check the complete registration body against its retained request hash.
    pub fn check_body(&self, raw: &[u8]) -> Result<()> {
        match self.kind {
            DiscoveryKind::Register { registration }
                if raw.len() <= MAX_REGISTRATION_BYTES && hash(raw) == registration =>
            {
                Ok(())
            }
            _ => Err(DiscoveryError::Scope),
        }
    }
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.nonce);
        match self.kind {
            DiscoveryKind::List {
                generation,
                after,
                count,
            } => {
                out.push(0);
                out.extend_from_slice(&generation.to_be_bytes());
                out.extend_from_slice(&after);
                out.push(count);
            }
            DiscoveryKind::Challenge {
                publisher,
                advertisement,
            } => {
                out.push(1);
                out.extend_from_slice(&publisher);
                out.extend_from_slice(&advertisement);
            }
            DiscoveryKind::Register { registration } => {
                out.push(2);
                out.extend_from_slice(&registration);
            }
        }
    }
    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        let nonce = r.array()?;
        let kind = match r.byte()? {
            0 => DiscoveryKind::List {
                generation: r.u64()?,
                after: r.array()?,
                count: r.byte()?,
            },
            1 => DiscoveryKind::Challenge {
                publisher: r.array()?,
                advertisement: r.array()?,
            },
            2 => DiscoveryKind::Register {
                registration: r.array()?,
            },
            _ => return Err(DiscoveryError::Encoding),
        };
        Self::new(nonce, kind)
    }
    fn body_bound(&self) -> usize {
        match self.kind {
            DiscoveryKind::List { .. } => MAX_PEER_PAGE_BYTES,
            DiscoveryKind::Challenge { .. } => REGISTRATION_CHALLENGE_BYTES,
            DiscoveryKind::Register { .. } => REGISTRATION_RECEIPT_BYTES,
        }
    }
}
fn split<'a>(s: &'a str, at: &str) -> Result<(&'a str, &'a str)> {
    s.split_once(at).ok_or(DiscoveryError::Encoding)
}
fn unhex(s: &str) -> Result<[u8; 32]> {
    if s.len() != 64
        || !s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(DiscoveryError::Encoding);
    }
    let mut out = [0; 32];
    for (i, v) in out.iter_mut().enumerate() {
        *v = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|_| DiscoveryError::Encoding)?;
    }
    Ok(out)
}
fn number(s: &str) -> Result<u64> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) || (s.len() > 1 && s.starts_with('0'))
    {
        return Err(DiscoveryError::Encoding);
    }
    s.parse().map_err(|_| DiscoveryError::Bounds)
}

/// Bounded listing with independently signed, strictly full-key-ordered route hints.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerPage {
    network: [u8; 32],
    generation: u64,
    after: [u8; 32],
    more: bool,
    advertisements: Vec<PeerAdvertisement>,
}
impl PeerPage {
    /// Build an exact page; no signature or freshness verification is implied.
    pub fn new(
        network: [u8; 32],
        generation: u64,
        after: [u8; 32],
        more: bool,
        advertisements: Vec<PeerAdvertisement>,
    ) -> Result<Self> {
        if network == [0; 32]
            || generation == 0
            || advertisements.len() > MAX_PEERS_PER_PAGE
            || (more && advertisements.is_empty())
        {
            return Err(DiscoveryError::Bounds);
        }
        let mut cursor = after;
        for ad in &advertisements {
            let c = ad.unverified_claims();
            if c.network != network || c.application_key <= cursor {
                return Err(DiscoveryError::Scope);
            }
            cursor = c.application_key;
        }
        Ok(Self {
            network,
            generation,
            after,
            more,
            advertisements,
        })
    }
    /// Strict canonical decode before independent subject signature verification.
    pub fn decode(raw: &[u8]) -> Result<Self> {
        let mut r = Reader::new(raw, MAX_PEER_PAGE_BYTES, b"VHPL\x01")?;
        let network = r.array()?;
        let generation = r.u64()?;
        let after = r.array()?;
        let more = r.boolean()?;
        let count = usize::from(r.byte()?);
        if count > MAX_PEERS_PER_PAGE {
            return Err(DiscoveryError::Bounds);
        }
        let mut ads = Vec::with_capacity(count);
        for _ in 0..count {
            let len = usize::from(r.u16()?);
            ads.push(
                PeerAdvertisement::decode(r.take(len)?).map_err(|_| DiscoveryError::Encoding)?,
            );
        }
        r.done()?;
        Self::new(network, generation, after, more, ads)
    }
    /// Exact bounded listing bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = b"VHPL\x01".to_vec();
        out.extend_from_slice(&self.network);
        out.extend_from_slice(&self.generation.to_be_bytes());
        out.extend_from_slice(&self.after);
        out.push(u8::from(self.more));
        out.push(self.advertisements.len() as u8);
        for ad in &self.advertisements {
            let raw = ad.encode();
            out.extend_from_slice(&(raw.len() as u16).to_be_bytes());
            out.extend_from_slice(&raw);
        }
        out
    }
    /// Network described; compare to the independent bootstrap-derived scope.
    pub const fn network_id(&self) -> [u8; 32] {
        self.network
    }
    /// Exact generation to send on continuation; a conflict requires restarting.
    pub const fn generation(&self) -> u64 {
        self.generation
    }
    /// Requested exclusive starting key.
    pub const fn after(&self) -> [u8; 32] {
        self.after
    }
    /// Complete final key, or the starting key for an empty terminal page.
    pub fn next_after(&self) -> [u8; 32] {
        self.advertisements
            .last()
            .map_or(self.after, |ad| ad.unverified_claims().application_key)
    }
    /// More candidates existed in this peer's local generation.
    pub const fn has_more(&self) -> bool {
        self.more
    }
    /// Untrusted subject descriptors. Verify independently and never auto-dial arbitrary DNS.
    pub fn advertisements(&self) -> &[PeerAdvertisement] {
        &self.advertisements
    }
    /// Bind page semantics to the retained listing request in addition to its outer proof.
    pub fn check_request(&self, network: [u8; 32], request: DiscoveryRequest) -> Result<()> {
        match request.kind {
            DiscoveryKind::List {
                generation,
                after,
                count,
            } if network == self.network
                && after == self.after
                && (generation == 0 || generation == self.generation)
                && self.advertisements.len() <= usize::from(count) =>
            {
                Ok(())
            }
            _ => Err(DiscoveryError::Scope),
        }
    }
}

/// Typed response statement; signatures bind the entire canonical request and body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnsignedDiscoveryResponse {
    network: [u8; 32],
    peer: [u8; 32],
    request: DiscoveryRequest,
    body: [u8; 32],
}
impl UnsignedDiscoveryResponse {
    /// Bind a successful body only, under independently selected network/key scope.
    pub fn new(
        network: [u8; 32],
        peer: [u8; 32],
        request: DiscoveryRequest,
        body: &[u8],
    ) -> Result<Self> {
        if network == [0; 32] {
            return Err(DiscoveryError::Scope);
        }
        key(&peer)?;
        if body.len() > request.body_bound() {
            return Err(DiscoveryError::Bounds);
        }
        Ok(Self {
            network,
            peer,
            request,
            body: hash(body),
        })
    }
    fn unsigned(&self) -> Vec<u8> {
        let mut o = b"VHDP\x01".to_vec();
        o.extend_from_slice(&self.network);
        o.extend_from_slice(&self.peer);
        self.request.encode_into(&mut o);
        o.extend_from_slice(&self.body);
        o
    }
    /// Exact domain-separated signing bytes for an external custody provider.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut o = RESPONSE_DOMAIN.to_vec();
        o.extend_from_slice(&self.unsigned());
        o
    }
    /// Attach and strictly verify a response signature.
    pub fn attach_signature(self, signature: [u8; 64]) -> Result<DiscoveryResponseProof> {
        let p = DiscoveryResponseProof {
            statement: self,
            signature,
        };
        p.check_signature()?;
        Ok(p)
    }
    /// Sign only with the response's complete peer key.
    pub fn sign_with_key(self, key: &SigningKey) -> Result<DiscoveryResponseProof> {
        if key.verifying_key().to_bytes() != self.peer {
            return Err(DiscoveryError::Scope);
        }
        let sig = key.sign(&self.signing_bytes()).to_bytes();
        self.attach_signature(sig)
    }
}
/// Fresh nonce-bound peer response; never a consensus or route-subject signature.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscoveryResponseProof {
    statement: UnsignedDiscoveryResponse,
    signature: [u8; 64],
}
impl DiscoveryResponseProof {
    /// Strict bounded proof decoding, before verification.
    pub fn decode(raw: &[u8]) -> Result<Self> {
        let mut r = Reader::new(raw, MAX_DISCOVERY_PROOF_BYTES, b"VHDP\x01")?;
        let network = r.array()?;
        let peer = r.array()?;
        let request = DiscoveryRequest::decode(&mut r)?;
        let body = r.array()?;
        let signature = r.array()?;
        r.done()?;
        key(&peer)?;
        if network == [0; 32] {
            return Err(DiscoveryError::Scope);
        }
        Ok(Self {
            statement: UnsignedDiscoveryResponse {
                network,
                peer,
                request,
                body,
            },
            signature,
        })
    }
    /// Exact proof bytes for the x-vhalla-proof header.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.statement.unsigned();
        out.extend_from_slice(&self.signature);
        out
    }
    fn check_signature(&self) -> Result<()> {
        crate::checked_key(&self.statement.peer)
            .map_err(|_| DiscoveryError::Signature)?
            .verify_strict(
                &self.statement.signing_bytes(),
                &Signature::from_bytes(&self.signature),
            )
            .map_err(|_| DiscoveryError::Signature)
    }
    /// Compare the retained exact request, independent scope/key, complete body and signature.
    pub fn verify(
        &self,
        network: [u8; 32],
        peer: [u8; 32],
        request: DiscoveryRequest,
        body: &[u8],
    ) -> Result<()> {
        let expected = UnsignedDiscoveryResponse::new(network, peer, request, body)?;
        if expected != self.statement {
            return Err(DiscoveryError::Scope);
        }
        self.check_signature()
    }
}

/// Decode the bounded canonical lowercase-hex discovery proof header.
pub fn proof_from_hex(raw: &str) -> Result<DiscoveryResponseProof> {
    if raw.len() > MAX_DISCOVERY_PROOF_BYTES * 2 || raw.len() & 1 != 0 {
        return Err(DiscoveryError::Bounds);
    }
    let mut bytes = Vec::with_capacity(raw.len() / 2);
    for pair in raw.as_bytes().as_chunks::<2>().0.iter() {
        let digit = |byte: u8| match byte {
            b'0'..=b'9' => Ok(byte - b'0'),
            b'a'..=b'f' => Ok(byte - b'a' + 10),
            _ => Err(DiscoveryError::Encoding),
        };
        bytes.push(digit(pair[0])? * 16 + digit(pair[1])?);
    }
    DiscoveryResponseProof::decode(&bytes)
}

fn context(network: [u8; 32], receiver: [u8; 32], publisher: [u8; 32]) -> ChallengeContext {
    ChallengeContext {
        issuer_key: receiver,
        subject_key: publisher,
        realm: RealmId(u128::from_be_bytes(
            network[..16].try_into().expect("fixed half"),
        )),
        room: RoomId(u128::from_be_bytes(
            network[16..].try_into().expect("fixed half"),
        )),
        purpose: Purpose::RateLimitRelief,
    }
}
fn challenge_id(
    network: [u8; 32],
    receiver: [u8; 32],
    publisher: [u8; 32],
    advertisement: [u8; 32],
    nonce: [u8; 32],
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(REQUEST_DOMAIN);
    for v in [network, receiver, publisher, advertisement, nonce] {
        h.update(v);
    }
    h.finalize().into()
}

/// Checked issuer request for the fixed discovery Hashcash contract.
#[derive(Clone, Debug)]
pub struct UnsignedRegistrationChallenge {
    network: [u8; 32],
    advertisement: [u8; 32],
    nonce: [u8; 32],
    challenge: Challenge,
}
impl UnsignedRegistrationChallenge {
    /// Issue only the exact discovery context. Known status is local registry evidence.
    pub fn new(
        network: [u8; 32],
        receiver: [u8; 32],
        request: DiscoveryRequest,
        issued_at: u64,
        known: bool,
    ) -> Result<Self> {
        let DiscoveryKind::Challenge {
            publisher,
            advertisement,
        } = request.kind
        else {
            return Err(DiscoveryError::Scope);
        };
        if network == [0; 32] {
            return Err(DiscoveryError::Scope);
        }
        key(&receiver)?;
        key(&publisher)?;
        let ctx = context(network, receiver, publisher);
        let challenge = Challenge {
            version: vhalla_botcaptcha::VERSION,
            algorithm: Algorithm::Hashcash,
            challenge_id: challenge_id(network, receiver, publisher, advertisement, request.nonce),
            issuer_key: receiver,
            subject_key: publisher,
            realm: ctx.realm,
            room: ctx.room,
            purpose: ctx.purpose,
            task_manifest_hash: ManifestHash([0; 32]),
            issued_at,
            expires_at: issued_at
                .checked_add(CHALLENGE_LIFETIME)
                .ok_or(DiscoveryError::Bounds)?,
            requirement: Requirement::Hashcash(
                Difficulty::new(if known {
                    KNOWN_PEER_DIFFICULTY
                } else {
                    NEW_PEER_DIFFICULTY
                })
                .expect("fixed difficulty"),
            ),
            signature: [0; 64],
        };
        Ok(Self {
            network,
            advertisement,
            nonce: request.nonce,
            challenge,
        })
    }
    /// Existing Botcaptcha challenge transcript, with discovery context committed by challenge_id.
    pub fn signing_bytes(&self) -> Vec<u8> {
        self.challenge.transcript()
    }
    /// Attach the receiver's strict signature without granting any other capability.
    pub fn attach_signature(mut self, signature: [u8; 64]) -> Result<RegistrationChallenge> {
        self.challenge.signature = signature;
        let c = RegistrationChallenge {
            network: self.network,
            advertisement: self.advertisement,
            nonce: self.nonce,
            challenge: self.challenge,
        };
        c.check(c.challenge.issued_at)?;
        Ok(c)
    }
    /// Sign with the exact receiving peer's application key.
    pub fn sign_with_key(self, key: &SigningKey) -> Result<RegistrationChallenge> {
        if key.verifying_key().to_bytes() != self.challenge.issuer_key {
            return Err(DiscoveryError::Scope);
        }
        let sig = key.sign(&self.signing_bytes()).to_bytes();
        self.attach_signature(sig)
    }
}
/// Receiver-signed work requirement bound to the full proposed advertisement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegistrationChallenge {
    network: [u8; 32],
    advertisement: [u8; 32],
    nonce: [u8; 32],
    challenge: Challenge,
}
impl RegistrationChallenge {
    /// Strict exact framing; verify before solving or trusting the cost.
    pub fn decode(raw: &[u8]) -> Result<Self> {
        let mut r = Reader::new(raw, REGISTRATION_CHALLENGE_BYTES, b"VHDC\x01")?;
        let network = r.array()?;
        let advertisement = r.array()?;
        let nonce = r.array()?;
        let challenge =
            Challenge::decode(r.take(CHALLENGE_BYTES)?).map_err(|_| DiscoveryError::Encoding)?;
        r.done()?;
        Ok(Self {
            network,
            advertisement,
            nonce,
            challenge,
        })
    }
    /// Canonical wrapper plus existing complete signed challenge.
    pub fn encode(&self) -> Vec<u8> {
        let mut o = b"VHDC\x01".to_vec();
        o.extend_from_slice(&self.network);
        o.extend_from_slice(&self.advertisement);
        o.extend_from_slice(&self.nonce);
        o.extend_from_slice(&self.challenge.encode());
        o
    }
    fn check(&self, now: u64) -> Result<VerifiedChallenge> {
        let c = &self.challenge;
        if self.network == [0; 32]
            || self.nonce == [0; 32]
            || c.algorithm != Algorithm::Hashcash
            || c.task_manifest_hash.0 != [0; 32]
            || c.expires_at.checked_sub(c.issued_at) != Some(CHALLENGE_LIFETIME)
            || c.challenge_id
                != challenge_id(
                    self.network,
                    c.issuer_key,
                    c.subject_key,
                    self.advertisement,
                    self.nonce,
                )
        {
            return Err(DiscoveryError::Scope);
        }
        if !matches!(
            c.difficulty().map(|d| d.bits()),
            Some(KNOWN_PEER_DIFFICULTY | NEW_PEER_DIFFICULTY)
        ) {
            return Err(DiscoveryError::Work);
        }
        if now >= c.expires_at {
            return Err(DiscoveryError::Time);
        }
        key(&c.subject_key)?;
        VerifiedChallenge::verify(
            c.clone(),
            context(self.network, c.issuer_key, c.subject_key),
            c.issued_at,
            now,
        )
        .map_err(|_| DiscoveryError::Signature)
    }
    /// Check an independently selected receiver/network and exact prior challenge request.
    pub fn verify(
        &self,
        network: [u8; 32],
        receiver: [u8; 32],
        request: DiscoveryRequest,
        now: u64,
    ) -> Result<VerifiedRegistrationChallenge> {
        if self.network != network
            || self.challenge.issuer_key != receiver
            || request.nonce != self.nonce
            || request.kind
                != (DiscoveryKind::Challenge {
                    publisher: self.challenge.subject_key,
                    advertisement: self.advertisement,
                })
        {
            return Err(DiscoveryError::Scope);
        }
        let checked = self.check(now)?;
        Ok(VerifiedRegistrationChallenge {
            raw: self.clone(),
            checked,
        })
    }
    /// Work difficulty is untrusted until verify() succeeds.
    pub fn difficulty(&self) -> Option<u8> {
        self.challenge.difficulty().map(|d| d.bits())
    }
    /// Exclusive signed expiration boundary.
    pub const fn expires_at(&self) -> u64 {
        self.challenge.expires_at
    }
}
/// Verified work challenge; no implicit solver loop or host authority.
#[derive(Debug)]
pub struct VerifiedRegistrationChallenge {
    raw: RegistrationChallenge,
    checked: VerifiedChallenge,
}
impl VerifiedRegistrationChallenge {
    /// Bounded solver. Returns Exhausted instead of retrying or silently raising its budget.
    pub fn solve(&self, max_attempts: u64) -> Result<u64> {
        if max_attempts == 0 || max_attempts > MAX_SOLVE_ATTEMPTS {
            return Err(DiscoveryError::Bounds);
        }
        vhalla_botcaptcha::hashcash::solve(&self.checked, max_attempts)
            .map_err(|_| DiscoveryError::Exhausted)
    }
    /// Incremental bounded search supports caller cancellation between chunks.
    pub fn solve_range(&self, start: u64, attempts: u64) -> Result<Option<u64>> {
        if attempts == 0 || attempts > MAX_SOLVE_ATTEMPTS {
            return Err(DiscoveryError::Bounds);
        }
        let end = start.checked_add(attempts).ok_or(DiscoveryError::Bounds)?;
        let c = self.checked.challenge();
        let bits = u32::from(c.difficulty().ok_or(DiscoveryError::Work)?.bits());
        let challenge_hash = c.hash();
        let subject = c.subject_key;
        Ok((start..end).find(|n| {
            vhalla_botcaptcha::hashcash::leading_zero_bits(
                &vhalla_botcaptcha::hashcash::work_digest(challenge_hash, subject, *n),
            ) >= bits
        }))
    }
    /// Verified difficulty, useful for displaying an explicit bounded work budget.
    pub fn difficulty(&self) -> u8 {
        self.checked
            .challenge()
            .difficulty()
            .expect("checked Hashcash")
            .bits()
    }
}
/// Fixed typed registration ready for subject signing through native or browser custody.
#[derive(Clone, Debug)]
pub struct UnsignedRegistration {
    advertisement: PeerAdvertisement,
    challenge: RegistrationChallenge,
    response: HashcashResponse,
}
impl UnsignedRegistration {
    /// Bind the exact signed advertisement and solved challenge before signing.
    pub fn new(
        advertisement: PeerAdvertisement,
        challenge: VerifiedRegistrationChallenge,
        nonce: u64,
    ) -> Result<Self> {
        if hash(&advertisement.encode()) != challenge.raw.advertisement
            || advertisement.unverified_claims().application_key
                != challenge.raw.challenge.subject_key
            || advertisement.unverified_claims().network != challenge.raw.network
        {
            return Err(DiscoveryError::Scope);
        }
        let c = challenge.checked.challenge();
        if vhalla_botcaptcha::hashcash::leading_zero_bits(
            &vhalla_botcaptcha::hashcash::work_digest(c.hash(), c.subject_key, nonce),
        ) < u32::from(c.difficulty().ok_or(DiscoveryError::Work)?.bits())
        {
            return Err(DiscoveryError::Work);
        }
        let response = HashcashResponse {
            version: vhalla_botcaptcha::VERSION,
            challenge_id: c.challenge_id,
            challenge_hash: c.hash(),
            subject_key: c.subject_key,
            nonce,
            signature: [0; 64],
        };
        Ok(Self {
            advertisement,
            challenge: challenge.raw,
            response,
        })
    }
    /// Existing full Botcaptcha Hashcash response transcript.
    pub fn signing_bytes(&self) -> Vec<u8> {
        self.response.transcript()
    }
    /// Attach and strictly verify subject possession; native admission also checks current time/floors.
    pub fn attach_signature(mut self, signature: [u8; 64]) -> Result<Registration> {
        self.response.signature = signature;
        crate::checked_key(&self.response.subject_key)
            .map_err(|_| DiscoveryError::Signature)?
            .verify_strict(
                &self.response.transcript(),
                &Signature::from_bytes(&signature),
            )
            .map_err(|_| DiscoveryError::Signature)?;
        Ok(Registration {
            advertisement: self.advertisement,
            challenge: self.challenge,
            response: self.response,
        })
    }
    /// Sign only with the exact publishing application key.
    pub fn sign_with_key(self, key: &SigningKey) -> Result<Registration> {
        if key.verifying_key().to_bytes() != self.response.subject_key {
            return Err(DiscoveryError::Scope);
        }
        let sig = key.sign(&self.signing_bytes()).to_bytes();
        self.attach_signature(sig)
    }
}
/// Canonical registration input: still untrusted before verify and registry admission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Registration {
    advertisement: PeerAdvertisement,
    challenge: RegistrationChallenge,
    response: HashcashResponse,
}
impl Registration {
    /// Exact bounded decode with no trailing bytes.
    pub fn decode(raw: &[u8]) -> Result<Self> {
        let mut r = Reader::new(raw, MAX_REGISTRATION_BYTES, b"VHDA\x01")?;
        let challenge = RegistrationChallenge::decode(r.take(REGISTRATION_CHALLENGE_BYTES)?)?;
        let n = usize::from(r.u16()?);
        let advertisement =
            PeerAdvertisement::decode(r.take(n)?).map_err(|_| DiscoveryError::Encoding)?;
        let response = HashcashResponse::decode(r.take(HASHCASH_RESPONSE_BYTES)?)
            .map_err(|_| DiscoveryError::Encoding)?;
        r.done()?;
        Ok(Self {
            advertisement,
            challenge,
            response,
        })
    }
    /// Exact signed registration bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut o = b"VHDA\x01".to_vec();
        o.extend_from_slice(&self.challenge.encode());
        let raw = self.advertisement.encode();
        o.extend_from_slice(&(raw.len() as u16).to_be_bytes());
        o.extend_from_slice(&raw);
        o.extend_from_slice(&self.response.encode());
        o
    }
    /// Public advertisement, explicitly untrusted until independently verified.
    pub const fn advertisement(&self) -> &PeerAdvertisement {
        &self.advertisement
    }
    /// Verify full challenge context, strict signatures, current freshness and hash work.
    /// A fresh volatile one-use window checks the existing verifier contract;
    /// the registry's durable exact-ad/sequence decision provides replay semantics.
    pub fn verify(
        &self,
        network: [u8; 32],
        receiver: [u8; 32],
        now: u64,
        known: bool,
    ) -> Result<VerifiedAdvertisement> {
        let c = &self.challenge;
        let a = self.advertisement.unverified_claims();
        if c.network != network
            || c.challenge.issuer_key != receiver
            || c.challenge.subject_key != a.application_key
            || c.advertisement != hash(&self.advertisement.encode())
        {
            return Err(DiscoveryError::Scope);
        }
        c.check(now)?;
        if !known && c.difficulty() != Some(NEW_PEER_DIFFICULTY) {
            return Err(DiscoveryError::Work);
        }
        let mut verifier = WitnessVerifier::new(
            c.challenge.issued_at,
            WorkAllowance { max_total: 0 },
            OneUseWindow::new(),
        );
        verifier
            .verify_hashcash(
                c.challenge.clone(),
                &self.response,
                context(network, receiver, a.application_key),
                now,
            )
            .map_err(|_| DiscoveryError::Work)?;
        self.advertisement
            .verify(
                &VerificationPolicy {
                    network,
                    now,
                    max_clock_skew_seconds: MAX_CLOCK_SKEW_SECONDS,
                    max_ttl_seconds: MAX_TTL_SECONDS,
                },
                None,
            )
            .map_err(|_| DiscoveryError::Time)
    }
}
/// Local durable registration receipt. It grants no endpoint reachability or authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegistrationReceipt {
    network: [u8; 32],
    receiver: [u8; 32],
    publisher: [u8; 32],
    sequence: u64,
    generation: u64,
    expires: u64,
    retained_until: u64,
}
impl RegistrationReceipt {
    /// Construct local receipt fields after a durable admission or exact retry.
    pub fn new(
        network: [u8; 32],
        receiver: [u8; 32],
        publisher: [u8; 32],
        sequence: u64,
        generation: u64,
        expires: u64,
        retained_until: u64,
    ) -> Result<Self> {
        if network == [0; 32] || sequence == 0 || generation == 0 || expires > retained_until {
            return Err(DiscoveryError::Bounds);
        }
        key(&receiver)?;
        key(&publisher)?;
        Ok(Self {
            network,
            receiver,
            publisher,
            sequence,
            generation,
            expires,
            retained_until,
        })
    }
    /// Strict bounded receipt decode; verify the outer response proof separately.
    pub fn decode(raw: &[u8]) -> Result<Self> {
        let mut r = Reader::new(raw, REGISTRATION_RECEIPT_BYTES, b"VHDR\x01")?;
        let v = Self::new(
            r.array()?,
            r.array()?,
            r.array()?,
            r.u64()?,
            r.u64()?,
            r.u64()?,
            r.u64()?,
        )?;
        r.done()?;
        Ok(v)
    }
    /// Exact canonical receipt bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut o = b"VHDR\x01".to_vec();
        for v in [self.network, self.receiver, self.publisher] {
            o.extend_from_slice(&v);
        }
        for v in [
            self.sequence,
            self.generation,
            self.expires,
            self.retained_until,
        ] {
            o.extend_from_slice(&v.to_be_bytes());
        }
        o
    }
    /// Bind a receipt to the exact signed descriptor submitted under the selected receiver.
    pub fn check(
        &self,
        network: [u8; 32],
        receiver: [u8; 32],
        advertisement: &PeerAdvertisement,
    ) -> Result<()> {
        let claims = advertisement.unverified_claims();
        if self.network != network
            || claims.network != network
            || self.receiver != receiver
            || self.publisher != claims.application_key
            || self.sequence != claims.sequence
            || self.expires != claims.expires_at
        {
            return Err(DiscoveryError::Scope);
        }
        Ok(())
    }
    /// Full network scope carried by this local receipt.
    pub const fn network_id(&self) -> [u8; 32] {
        self.network
    }
    /// Full peer key whose registry made the local admission.
    pub const fn receiver(&self) -> [u8; 32] {
        self.receiver
    }
    /// Full registered publisher key.
    pub const fn publisher(&self) -> [u8; 32] {
        self.publisher
    }
    /// Exact admitted advertisement sequence.
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }
    /// Local registry generation after admission.
    pub const fn generation(&self) -> u64 {
        self.generation
    }
    /// Advertisement expiration; receipt does not extend it.
    pub const fn expires_at(&self) -> u64 {
        self.expires
    }
    /// Earliest retirement of this registry's temporary replay floor.
    pub const fn retained_until(&self) -> u64 {
        self.retained_until
    }
}

struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn new(raw: &'a [u8], max: usize, magic: &[u8]) -> Result<Self> {
        if raw.len() > max {
            return Err(DiscoveryError::Bounds);
        }
        if !raw.starts_with(magic) {
            return Err(DiscoveryError::Encoding);
        }
        Ok(Self(&raw[magic.len()..]))
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if n > self.0.len() {
            return Err(DiscoveryError::Encoding);
        }
        let (v, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(v)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.take(N)?
            .try_into()
            .map_err(|_| DiscoveryError::Encoding)
    }
    fn byte(&mut self) -> Result<u8> {
        Ok(self.array::<1>()?[0])
    }
    fn boolean(&mut self) -> Result<bool> {
        match self.byte()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(DiscoveryError::Encoding),
        }
    }
    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.array()?))
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    fn done(&self) -> Result<()> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(DiscoveryError::Encoding)
        }
    }
}

#[cfg(test)]
mod tests;
