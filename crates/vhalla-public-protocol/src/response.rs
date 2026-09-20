//! Canonical GET requests, bounded pages and fresh nonce-bound peer responses.
//!
//! A proof authenticates one response from one full application key. It grants
//! no room/validator authority, and an observed HEAD is not global freshness.
//! Callers generate a fresh unpredictable nonce per attempt, retain the exact
//! request, enforce response byte/time budgets, and verify certificates/replay.
use alloc::{format, string::String, vec::Vec};
use ed25519_dalek::{Signature, Signer, SigningKey};
use sha2::{Digest, Sha256};

const PROOF_MAGIC: &[u8; 5] = b"VHPR\x01";
const PAGE_MAGIC: &[u8; 5] = b"VHPG\x01";
const DOMAIN: &[u8] = b"vhalla/public-peer-response/v1\0";
/// Canonical origin-form request-target ceiling.
pub const MAX_REQUEST_TARGET: usize = 512;
/// Hard page count ceiling.
pub const MAX_PAGE_BUNDLES: usize = 32;
/// Hard sum of opaque bundle bytes per page.
pub const MAX_PAGE_BYTES: usize = 2 * 1024 * 1024;
/// Maximum encoded page, including fixed framing and length prefixes.
pub const MAX_PAGE_FRAME_BYTES: usize = 5 + 8 + 32 + 8 + 1 + MAX_PAGE_BUNDLES * 4 + MAX_PAGE_BYTES;
/// Fixed upper proof size (the bundle request is the longest request).
pub const MAX_RESPONSE_PROOF_BYTES: usize = 5 + 32 + 32 + 32 + 1 + 8 + 32 + 1 + 4 + 32 + 64;
/// Portable bootstrap response hash ceiling; its decoder applies tighter bounds.
pub const MAX_BOOTSTRAP_RESPONSE_BYTES: usize = 40 * 1024 * 1024;
/// HTTP response header carrying lowercase hex of the canonical proof.
pub const PROOF_HEADER: &str = "x-vhalla-proof";

/// Rejection before treating a response as peer-authenticated.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResponseError {
    /// Count, size or arithmetic exceeded a ceiling.
    Bounds,
    /// Noncanonical, unsupported or truncated encoding.
    Encoding,
    /// Nonce is zero or differs from the retained request.
    Nonce,
    /// Invalid/weak full key or a different expected signer.
    Peer,
    /// Network differs from independently trusted scope.
    Network,
    /// Response is for a different typed request.
    Request,
    /// Response body differs from the signed digest.
    Body,
    /// Strict Ed25519 verification failed.
    Signature,
}

/// The complete semantics of a read-only request, excluding its nonce.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadKind {
    /// This peer's explicitly configured route advertisement.
    Advertisement,
    /// Exact independently pinned bootstrap artifact.
    Bootstrap,
    /// Bounded forward continuation from a complete known frontier.
    Bundles {
        /// Last installed height, zero for genesis.
        after: u64,
        /// Full commitment at `after`, never a short routing handle.
        frontier: [u8; 32],
        /// Nonzero maximum returned bundles, at most 32.
        count: u8,
        /// Nonzero maximum sum of bundle bytes, at most 2 MiB.
        bytes: u32,
    },
}

/// Immutable canonical GET context retained by the caller before making a call.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReadRequest {
    nonce: [u8; 32],
    kind: ReadKind,
}

impl ReadRequest {
    /// Check a caller-generated fresh nonce and bounded request fields.
    pub fn new(nonce: [u8; 32], kind: ReadKind) -> Result<Self, ResponseError> {
        if nonce == [0; 32] {
            return Err(ResponseError::Nonce);
        }
        if let ReadKind::Bundles { count, bytes, .. } = kind {
            if count == 0
                || usize::from(count) > MAX_PAGE_BUNDLES
                || bytes == 0
                || u64::from(bytes) > MAX_PAGE_BYTES as u64
            {
                return Err(ResponseError::Bounds);
            }
        }
        Ok(Self { nonce, kind })
    }
    /// Freshness challenge; uniqueness/entropy are the caller's responsibility.
    pub const fn nonce(&self) -> [u8; 32] {
        self.nonce
    }
    /// Exact read semantics.
    pub const fn kind(&self) -> ReadKind {
        self.kind
    }
    /// Exact canonical origin-form GET target, with no arbitrary paths.
    pub fn target(&self) -> String {
        let nonce = hex(&self.nonce);
        match self.kind {
            ReadKind::Advertisement => format!("/vhalla/v1?nonce={nonce}"),
            ReadKind::Bootstrap => format!("/vhalla/v1/bootstrap?nonce={nonce}"),
            ReadKind::Bundles { after, frontier, count, bytes } => format!("/vhalla/v1/bundles?after={after}&frontier={}&count={count}&bytes={bytes}&nonce={nonce}", hex(&frontier)),
        }
    }
    /// Parse only the exact supported target; parameter order is canonical.
    pub fn parse_target(target: &str) -> Result<Self, ResponseError> {
        if target.len() > MAX_REQUEST_TARGET {
            return Err(ResponseError::Bounds);
        }
        let request = if let Some(nonce) = target.strip_prefix("/vhalla/v1?nonce=") {
            Self::new(unhex32(nonce)?, ReadKind::Advertisement)?
        } else if let Some(nonce) = target.strip_prefix("/vhalla/v1/bootstrap?nonce=") {
            Self::new(unhex32(nonce)?, ReadKind::Bootstrap)?
        } else if let Some(rest) = target.strip_prefix("/vhalla/v1/bundles?after=") {
            let (after, rest) = rest
                .split_once("&frontier=")
                .ok_or(ResponseError::Encoding)?;
            let (frontier, rest) = rest.split_once("&count=").ok_or(ResponseError::Encoding)?;
            let (count, rest) = rest.split_once("&bytes=").ok_or(ResponseError::Encoding)?;
            let (bytes, nonce) = rest.split_once("&nonce=").ok_or(ResponseError::Encoding)?;
            Self::new(
                unhex32(nonce)?,
                ReadKind::Bundles {
                    after: decimal(after)?,
                    frontier: unhex32(frontier)?,
                    count: u8::try_from(decimal(count)?).map_err(|_| ResponseError::Bounds)?,
                    bytes: u32::try_from(decimal(bytes)?).map_err(|_| ResponseError::Bounds)?,
                },
            )?
        } else {
            return Err(ResponseError::Encoding);
        };
        if request.target() != target {
            return Err(ResponseError::Encoding);
        }
        Ok(request)
    }
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.nonce);
        match self.kind {
            ReadKind::Advertisement => out.push(0),
            ReadKind::Bootstrap => out.push(1),
            ReadKind::Bundles {
                after,
                frontier,
                count,
                bytes,
            } => {
                out.push(2);
                out.extend_from_slice(&after.to_be_bytes());
                out.extend_from_slice(&frontier);
                out.push(count);
                out.extend_from_slice(&bytes.to_be_bytes());
            }
        }
    }
    fn decode(input: &mut Reader<'_>) -> Result<Self, ResponseError> {
        let nonce = input.array()?;
        let kind = match input.array::<1>()?[0] {
            0 => ReadKind::Advertisement,
            1 => ReadKind::Bootstrap,
            2 => ReadKind::Bundles {
                after: input.u64()?,
                frontier: input.array()?,
                count: input.array::<1>()?[0],
                bytes: input.u32()?,
            },
            _ => return Err(ResponseError::Encoding),
        };
        Self::new(nonce, kind)
    }
    fn body_bound(&self) -> usize {
        match self.kind {
            ReadKind::Advertisement => crate::MAX_ADVERTISEMENT_BYTES,
            ReadKind::Bootstrap => MAX_BOOTSTRAP_RESPONSE_BYTES,
            ReadKind::Bundles { .. } => MAX_PAGE_FRAME_BYTES,
        }
    }
}

/// Typed unsigned successful-response statement for a custody signing provider.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnsignedResponse {
    network: [u8; 32],
    key: [u8; 32],
    request: ReadRequest,
    hash: [u8; 32],
}
impl UnsignedResponse {
    /// Bind the complete successful HTTP-200 body and exact GET context.
    pub fn new(
        network: [u8; 32],
        key: [u8; 32],
        request: ReadRequest,
        body: &[u8],
    ) -> Result<Self, ResponseError> {
        if network == [0; 32] {
            return Err(ResponseError::Network);
        }
        crate::checked_key(&key).map_err(|_| ResponseError::Peer)?;
        if body.len() > request.body_bound() {
            return Err(ResponseError::Bounds);
        }
        Ok(Self {
            network,
            key,
            request,
            hash: Sha256::digest(body).into(),
        })
    }
    fn encode_unsigned(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(MAX_RESPONSE_PROOF_BYTES);
        out.extend_from_slice(PROOF_MAGIC);
        out.extend_from_slice(&self.network);
        out.extend_from_slice(&self.key);
        self.request.encode_into(&mut out);
        out.extend_from_slice(&self.hash);
        out
    }
    /// Domain-separated Ed25519 message, usable by asynchronous external custody.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut out = DOMAIN.to_vec();
        out.extend_from_slice(&self.encode_unsigned());
        out
    }
    /// Attach a detached signature and strictly check it against the full key.
    pub fn attach_signature(self, signature: [u8; 64]) -> Result<PeerResponseProof, ResponseError> {
        let proof = PeerResponseProof {
            statement: self,
            signature,
        };
        proof.check_signature()?;
        Ok(proof)
    }
    /// Sign this typed statement with a matching application key.
    pub fn sign_with_key(self, key: &SigningKey) -> Result<PeerResponseProof, ResponseError> {
        if self.key != key.verifying_key().to_bytes() {
            return Err(ResponseError::Peer);
        }
        let signature = key.sign(&self.signing_bytes()).to_bytes();
        self.attach_signature(signature)
    }
}

/// Decoded but untrusted response proof. Verification requires all caller pins.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerResponseProof {
    statement: UnsignedResponse,
    signature: [u8; 64],
}
impl PeerResponseProof {
    /// Canonical proof bytes, typically lowercase-hex encoded in PROOF_HEADER.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.statement.encode_unsigned();
        out.extend_from_slice(&self.signature);
        out
    }
    /// Decode bounded canonical fields; this grants no trust.
    pub fn decode(raw: &[u8]) -> Result<Self, ResponseError> {
        if raw.len() > MAX_RESPONSE_PROOF_BYTES {
            return Err(ResponseError::Bounds);
        }
        let mut input = Reader(raw);
        if input.take(5)? != PROOF_MAGIC {
            return Err(ResponseError::Encoding);
        }
        let network = input.array()?;
        let key = input.array()?;
        let request = ReadRequest::decode(&mut input)?;
        let hash = input.array()?;
        let signature = input.array()?;
        if !input.0.is_empty() {
            return Err(ResponseError::Encoding);
        }
        if network == [0; 32] {
            return Err(ResponseError::Network);
        }
        crate::checked_key(&key).map_err(|_| ResponseError::Peer)?;
        Ok(Self {
            statement: UnsignedResponse {
                network,
                key,
                request,
                hash,
            },
            signature,
        })
    }
    /// Verify a successful response against the independently retained key,
    /// network, exact fresh request and received body. Never derive these
    /// expected values from this proof or an unauthenticated response header.
    pub fn verify(
        &self,
        network: [u8; 32],
        key: [u8; 32],
        request: &ReadRequest,
        body: &[u8],
    ) -> Result<VerifiedResponse, ResponseError> {
        let statement = &self.statement;
        if network != statement.network {
            return Err(ResponseError::Network);
        }
        if key != statement.key {
            return Err(ResponseError::Peer);
        }
        if request.nonce != statement.request.nonce {
            return Err(ResponseError::Nonce);
        }
        if request != &statement.request {
            return Err(ResponseError::Request);
        }
        if body.len() > request.body_bound() {
            return Err(ResponseError::Bounds);
        }
        if <[u8; 32]>::from(Sha256::digest(body)) != statement.hash {
            return Err(ResponseError::Body);
        }
        self.check_signature()?;
        Ok(VerifiedResponse {
            network,
            key,
            request: *request,
            hash: statement.hash,
        })
    }
    fn check_signature(&self) -> Result<(), ResponseError> {
        crate::checked_key(&self.statement.key)
            .map_err(|_| ResponseError::Peer)?
            .verify_strict(
                &self.statement.signing_bytes(),
                &Signature::from_bytes(&self.signature),
            )
            .map_err(|_| ResponseError::Signature)
    }
}
/// Immutable evidence of one peer-authenticated body, never consensus authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedResponse {
    network: [u8; 32],
    key: [u8; 32],
    request: ReadRequest,
    hash: [u8; 32],
}
impl VerifiedResponse {
    /// Independently expected immutable network scope.
    pub const fn network(&self) -> [u8; 32] {
        self.network
    }
    /// Complete authenticated application identity.
    pub const fn application_key(&self) -> [u8; 32] {
        self.key
    }
    /// Exact retained GET context, including freshness challenge.
    pub const fn request(&self) -> ReadRequest {
        self.request
    }
    /// SHA-256 digest of the authenticated body bytes.
    pub const fn body_hash(&self) -> [u8; 32] {
        self.hash
    }
}

/// Bounded opaque certified-bundle carrier. Contents still need client replay.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BundlePage {
    head: u64,
    frontier: [u8; 32],
    next: u64,
    bundles: Vec<Vec<u8>>,
}
impl BundlePage {
    /// Construct a page matching the exact request and this peer's observed HEAD.
    pub fn new(
        request: &ReadRequest,
        head: u64,
        frontier: [u8; 32],
        bundles: Vec<Vec<u8>>,
    ) -> Result<Self, ResponseError> {
        let ReadKind::Bundles {
            after,
            count,
            bytes,
            ..
        } = request.kind
        else {
            return Err(ResponseError::Request);
        };
        let next = after
            .checked_add(bundles.len() as u64)
            .ok_or(ResponseError::Bounds)?;
        if bundles.len() > usize::from(count) || next > head || (bundles.is_empty() && after < head)
        {
            return Err(ResponseError::Bounds);
        }
        let mut total = 0usize;
        for bundle in &bundles {
            if bundle.is_empty() {
                return Err(ResponseError::Encoding);
            }
            total = total
                .checked_add(bundle.len())
                .filter(|n| *n <= bytes as usize)
                .ok_or(ResponseError::Bounds)?;
        }
        Ok(Self {
            head,
            frontier,
            next,
            bundles,
        })
    }
    /// Parse an exact bounded frame matching the caller's request limits/cursor.
    pub fn decode(raw: &[u8], request: &ReadRequest) -> Result<Self, ResponseError> {
        if raw.len() > MAX_PAGE_FRAME_BYTES {
            return Err(ResponseError::Bounds);
        }
        let mut input = Reader(raw);
        if input.take(5)? != PAGE_MAGIC {
            return Err(ResponseError::Encoding);
        }
        let head = input.u64()?;
        let frontier = input.array()?;
        let next = input.u64()?;
        let count = usize::from(input.array::<1>()?[0]);
        if count > MAX_PAGE_BUNDLES {
            return Err(ResponseError::Bounds);
        }
        let mut bundles = Vec::with_capacity(count);
        let mut total = 0usize;
        for _ in 0..count {
            let len = usize::try_from(input.u32()?).map_err(|_| ResponseError::Bounds)?;
            total = total
                .checked_add(len)
                .filter(|n| *n <= MAX_PAGE_BYTES)
                .ok_or(ResponseError::Bounds)?;
            bundles.push(input.take(len)?.to_vec());
        }
        if !input.0.is_empty() {
            return Err(ResponseError::Encoding);
        }
        let page = Self::new(request, head, frontier, bundles)?;
        if next != page.next {
            return Err(ResponseError::Encoding);
        }
        Ok(page)
    }
    /// Canonical page bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(PAGE_MAGIC);
        out.extend_from_slice(&self.head.to_be_bytes());
        out.extend_from_slice(&self.frontier);
        out.extend_from_slice(&self.next.to_be_bytes());
        out.push(self.bundles.len() as u8);
        for bundle in &self.bundles {
            out.extend_from_slice(&(bundle.len() as u32).to_be_bytes());
            out.extend_from_slice(bundle);
        }
        out
    }
    /// Peer-local observed height, not proof of latest global height.
    pub const fn observed_height(&self) -> u64 {
        self.head
    }
    /// Peer-local observed frontier, independently checked if replay reaches it.
    pub const fn observed_frontier(&self) -> [u8; 32] {
        self.frontier
    }
    /// Last encoded height, or the original cursor for an empty page.
    pub const fn next_after(&self) -> u64 {
        self.next
    }
    /// Opaque canonical bundle bytes in consecutive ascending order.
    pub fn bundles(&self) -> &[Vec<u8>] {
        &self.bundles
    }
    /// Continuation exists below the same peer-local observed HEAD.
    pub const fn has_more(&self) -> bool {
        self.next < self.head
    }
}

/// Lowercase hex for fixed protocol bytes; no ambiguous text encoding.
pub fn hex(raw: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(raw.len() * 2);
    for &byte in raw {
        out.push(DIGITS[usize::from(byte >> 4)] as char);
        out.push(DIGITS[usize::from(byte & 15)] as char);
    }
    out
}
/// Decode a bounded lowercase hex proof header to canonical bytes.
pub fn proof_from_hex(raw: &str) -> Result<PeerResponseProof, ResponseError> {
    if raw.len() > MAX_RESPONSE_PROOF_BYTES * 2 || raw.len() & 1 != 0 {
        return Err(ResponseError::Bounds);
    }
    let mut out = Vec::with_capacity(raw.len() / 2);
    for pair in raw.as_bytes().as_chunks::<2>().0.iter() {
        out.push(nibble(pair[0])? * 16 + nibble(pair[1])?);
    }
    PeerResponseProof::decode(&out)
}
fn unhex32(raw: &str) -> Result<[u8; 32], ResponseError> {
    if raw.len() != 64 {
        return Err(ResponseError::Encoding);
    }
    let mut out = [0; 32];
    for (slot, pair) in out.iter_mut().zip(raw.as_bytes().as_chunks::<2>().0.iter()) {
        *slot = nibble(pair[0])? * 16 + nibble(pair[1])?;
    }
    Ok(out)
}
fn nibble(byte: u8) -> Result<u8, ResponseError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(ResponseError::Encoding),
    }
}
fn decimal(raw: &str) -> Result<u64, ResponseError> {
    if raw.is_empty()
        || (raw.len() > 1 && raw.starts_with('0'))
        || !raw.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(ResponseError::Encoding);
    }
    raw.parse().map_err(|_| ResponseError::Bounds)
}
struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, size: usize) -> Result<&'a [u8], ResponseError> {
        let out = self.0.get(..size).ok_or(ResponseError::Encoding)?;
        self.0 = &self.0[size..];
        Ok(out)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], ResponseError> {
        self.take(N)?
            .try_into()
            .map_err(|_| ResponseError::Encoding)
    }
    fn u64(&mut self) -> Result<u64, ResponseError> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    fn u32(&mut self) -> Result<u32, ResponseError> {
        Ok(u32::from_be_bytes(self.array()?))
    }
}

#[cfg(test)]
mod tests;
