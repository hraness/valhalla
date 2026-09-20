//! Canonical public activity requests and peer-authenticated local durability
//! replies. Neither a receipt nor an observed certified frontier proves globally
//! latest policy, consensus admission of activity, delivery, or complete history.
use crate::response::{hex, ResponseError};
use alloc::{format, string::String, vec::Vec};
use ed25519_dalek::{Signature, Signer, SigningKey};
use sha2::{Digest, Sha256};
use vhalla_room_activity::{EventId, SignedEvent, VerifiedEvent, MAX_EVENT_BYTES};

const PROOF_MAGIC: &[u8; 5] = b"VHAP\x01";
const RECEIPT_MAGIC: &[u8; 5] = b"VHAL\x01";
const PAGE_MAGIC: &[u8; 5] = b"VHAG\x01";
const DOMAIN: &[u8] = b"vhalla/public-activity-response/v1\0";
/// Hard page count ceiling; each signed event is separately bounded.
pub const MAX_ACTIVITY_PAGE: usize = 32;
/// Exact fixed local receipt encoding size.
pub const RECEIPT_BYTES: usize = 5 + 32 * 5 + 8 * 3 + 1;
/// Upper bound on a framed activity history page.
pub const MAX_ACTIVITY_PAGE_BYTES: usize =
    5 + 8 + 8 + 32 + 1 + MAX_ACTIVITY_PAGE * (8 + 32 + 2 + MAX_EVENT_BYTES);
/// Upper bound for either canonical activity response proof.
pub const MAX_ACTIVITY_PROOF_BYTES: usize = 5 + 32 + 32 + 32 + 32 + 1 + 32 + 32 + 64;
/// Request target ceiling, including full IDs and fresh challenge.
pub const MAX_ACTIVITY_TARGET: usize = 320;

/// Exact request semantics. Author proof and room policy admission are separate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActivityKind {
    /// Publish exactly this SHA-256 committed signed frame locally.
    Post {
        /// Hash of the complete signed HTTP request body.
        body_hash: [u8; 32],
    },
    /// Read forward by local ordinal, not global time or author sequence.
    Page {
        /// Last consumed local cursor, zero to start.
        after: u64,
        /// Nonzero count, at most MAX_ACTIVITY_PAGE.
        count: u8,
    },
}
/// Immutable fresh challenge and exact full room/operation binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActivityRequest {
    nonce: [u8; 32],
    room: [u8; 32],
    kind: ActivityKind,
}
impl ActivityRequest {
    /// Bind a bounded exact signed POST body; this does not verify its signature.
    pub fn post(nonce: [u8; 32], room: [u8; 32], body: &[u8]) -> Result<Self, ResponseError> {
        if body.is_empty() || body.len() > MAX_EVENT_BYTES {
            return Err(ResponseError::Bounds);
        }
        Self::new(
            nonce,
            room,
            ActivityKind::Post {
                body_hash: Sha256::digest(body).into(),
            },
        )
    }
    /// Construct a bounded page request. Nonce entropy/uniqueness is caller-owned.
    pub fn page(
        nonce: [u8; 32],
        room: [u8; 32],
        after: u64,
        count: u8,
    ) -> Result<Self, ResponseError> {
        Self::new(nonce, room, ActivityKind::Page { after, count })
    }
    fn new(nonce: [u8; 32], room: [u8; 32], kind: ActivityKind) -> Result<Self, ResponseError> {
        if nonce == [0; 32] {
            return Err(ResponseError::Nonce);
        }
        if let ActivityKind::Page { count, .. } = kind {
            if count == 0 || usize::from(count) > MAX_ACTIVITY_PAGE {
                return Err(ResponseError::Bounds);
            }
        }
        Ok(Self { nonce, room, kind })
    }
    /// Exact operation parameters.
    pub const fn kind(&self) -> ActivityKind {
        self.kind
    }
    /// Full room genesis, never a shortened routing handle.
    pub const fn room(&self) -> [u8; 32] {
        self.room
    }
    /// Fresh challenge from the requesting client.
    pub const fn nonce(&self) -> [u8; 32] {
        self.nonce
    }
    /// Canonical origin-form target. POST and GET semantics are distinguished.
    pub fn target(&self) -> String {
        match self.kind {
            ActivityKind::Post { body_hash } => format!(
                "/vhalla/v1/activity?room={}&event={}&nonce={}",
                hex(&self.room),
                hex(&body_hash),
                hex(&self.nonce)
            ),
            ActivityKind::Page { after, count } => format!(
                "/vhalla/v1/activity?room={}&after={after}&count={count}&nonce={}",
                hex(&self.room),
                hex(&self.nonce)
            ),
        }
    }
    /// Decode only exact canonical target syntax and parameter order.
    pub fn parse_target(target: &str) -> Result<Self, ResponseError> {
        if target.len() > MAX_ACTIVITY_TARGET {
            return Err(ResponseError::Bounds);
        }
        let rest = target
            .strip_prefix("/vhalla/v1/activity?room=")
            .ok_or(ResponseError::Encoding)?;
        let (room, rest) = rest.split_once('&').ok_or(ResponseError::Encoding)?;
        let room = unhex32(room)?;
        let request = if let Some(rest) = rest.strip_prefix("event=") {
            let (hash, nonce) = rest.split_once("&nonce=").ok_or(ResponseError::Encoding)?;
            Self::new(
                unhex32(nonce)?,
                room,
                ActivityKind::Post {
                    body_hash: unhex32(hash)?,
                },
            )?
        } else if let Some(rest) = rest.strip_prefix("after=") {
            let (after, rest) = rest.split_once("&count=").ok_or(ResponseError::Encoding)?;
            let (count, nonce) = rest.split_once("&nonce=").ok_or(ResponseError::Encoding)?;
            Self::page(
                unhex32(nonce)?,
                room,
                decimal(after)?,
                u8::try_from(decimal(count)?).map_err(|_| ResponseError::Bounds)?,
            )?
        } else {
            return Err(ResponseError::Encoding);
        };
        if request.target() != target {
            return Err(ResponseError::Encoding);
        }
        Ok(request)
    }
    /// Check the complete body against the exact POST request hash and byte bound.
    pub fn check_body(&self, body: &[u8]) -> Result<(), ResponseError> {
        let ActivityKind::Post { body_hash } = self.kind else {
            return Err(ResponseError::Request);
        };
        if body.is_empty() || body.len() > MAX_EVENT_BYTES {
            return Err(ResponseError::Bounds);
        }
        if Sha256::digest(body).as_slice() != body_hash {
            return Err(ResponseError::Body);
        }
        Ok(())
    }
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.room);
        match self.kind {
            ActivityKind::Post { body_hash } => {
                out.push(0);
                out.extend_from_slice(&body_hash);
            }
            ActivityKind::Page { after, count } => {
                out.push(1);
                out.extend_from_slice(&after.to_be_bytes());
                out.push(count);
            }
        }
    }
    fn decode(r: &mut Reader<'_>) -> Result<Self, ResponseError> {
        let nonce = r.array()?;
        let room = r.array()?;
        let kind = match r.take(1)?[0] {
            0 => ActivityKind::Post {
                body_hash: r.array()?,
            },
            1 => ActivityKind::Page {
                after: r.u64()?,
                count: r.take(1)?[0],
            },
            _ => return Err(ResponseError::Encoding),
        };
        Self::new(nonce, room, kind)
    }
    fn body_bound(&self) -> usize {
        match self.kind {
            ActivityKind::Post { .. } => RECEIPT_BYTES,
            ActivityKind::Page { .. } => MAX_ACTIVITY_PAGE_BYTES,
        }
    }
}

/// A peer's local durable-storage statement. Trust only after verifying its
/// enclosing nonce-bound proof. It is not a consensus or current-policy receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalReceipt {
    room: [u8; 32],
    event_id: EventId,
    author: [u8; 32],
    sequence: u64,
    cursor: u64,
    registry: [u8; 32],
    height: u64,
    frontier: [u8; 32],
    reconciled: bool,
}
impl LocalReceipt {
    /// Build from a successfully stored signed event and separately observed
    /// certified frontier. Registry is the event's ORIGINAL local admission basis.
    pub fn new(
        event: &VerifiedEvent,
        cursor: u64,
        registry: [u8; 32],
        observed_height: u64,
        observed_frontier: [u8; 32],
        reconciled: bool,
    ) -> Result<Self, ResponseError> {
        if cursor == 0 {
            return Err(ResponseError::Bounds);
        }
        let c = event.claims();
        Ok(Self {
            room: *c.scope.room.as_bytes(),
            event_id: event.id(),
            author: c.author,
            sequence: c.sequence,
            cursor,
            registry,
            height: observed_height,
            frontier: observed_frontier,
            reconciled,
        })
    }
    /// Full room genesis named by the stored event.
    pub const fn room(&self) -> [u8; 32] {
        self.room
    }
    /// Full signed content commitment.
    pub const fn event_id(&self) -> EventId {
        self.event_id
    }
    /// Full application key attributed by the original event signature.
    pub const fn author(&self) -> [u8; 32] {
        self.author
    }
    /// Original event's per-author sequence.
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }
    /// Durable local ordinal at this particular peer.
    pub const fn local_cursor(&self) -> u64 {
        self.cursor
    }
    /// Original policy evaluation basis; an exact retry does not refresh it.
    pub const fn registry_digest(&self) -> [u8; 32] {
        self.registry
    }
    /// Certified height locally observed when handling this reply, not global latest.
    pub const fn observed_height(&self) -> u64 {
        self.height
    }
    /// Complete locally observed certified frontier commitment.
    pub const fn observed_frontier(&self) -> [u8; 32] {
        self.frontier
    }
    /// Exact prior result/recovery, not a newly admitted post.
    pub const fn reconciled(&self) -> bool {
        self.reconciled
    }
    /// Canonical bounded receipt body; authenticity requires enclosing proof.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = RECEIPT_MAGIC.to_vec();
        out.extend_from_slice(&self.room);
        out.extend_from_slice(self.event_id.as_bytes());
        out.extend_from_slice(&self.author);
        out.extend_from_slice(&self.sequence.to_be_bytes());
        out.extend_from_slice(&self.cursor.to_be_bytes());
        out.extend_from_slice(&self.registry);
        out.extend_from_slice(&self.height.to_be_bytes());
        out.extend_from_slice(&self.frontier);
        out.push(u8::from(self.reconciled));
        out
    }
    /// Decode exact local claims without authenticating the peer or event.
    pub fn decode(raw: &[u8]) -> Result<Self, ResponseError> {
        if raw.len() != RECEIPT_BYTES {
            return Err(ResponseError::Bounds);
        }
        let mut r = Reader(raw);
        if r.take(5)? != RECEIPT_MAGIC {
            return Err(ResponseError::Encoding);
        }
        let out = Self {
            room: r.array()?,
            event_id: EventId::from_bytes(r.array()?),
            author: r.array()?,
            sequence: r.u64()?,
            cursor: r.u64()?,
            registry: r.array()?,
            height: r.u64()?,
            frontier: r.array()?,
            reconciled: match r.take(1)?[0] {
                0 => false,
                1 => true,
                _ => return Err(ResponseError::Encoding),
            },
        };
        r.end()?;
        crate::checked_key(&out.author).map_err(|_| ResponseError::Peer)?;
        if out.sequence == 0 || out.cursor == 0 {
            return Err(ResponseError::Bounds);
        }
        Ok(out)
    }
}
/// One attributed event with local storage metadata; original admission is not
/// independently certified merely because this entry was returned by a peer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActivityEntry {
    cursor: u64,
    registry: [u8; 32],
    event: VerifiedEvent,
}
impl ActivityEntry {
    /// Construct one local page entry; event is strictly signature-verified.
    pub fn new(
        cursor: u64,
        registry: [u8; 32],
        event: VerifiedEvent,
    ) -> Result<Self, ResponseError> {
        if cursor == 0 {
            return Err(ResponseError::Bounds);
        }
        Ok(Self {
            cursor,
            registry,
            event,
        })
    }
    /// Local publication cursor at this peer only.
    pub const fn cursor(&self) -> u64 {
        self.cursor
    }
    /// Original local admission basis, not a certificate.
    pub const fn registry_digest(&self) -> [u8; 32] {
        self.registry
    }
    /// Authenticated author bytes, without inferred current admission authority.
    pub const fn event(&self) -> &VerifiedEvent {
        &self.event
    }
}
/// Bounded local disk-history page. Ordering is local publication order only.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActivityPage {
    tip: u64,
    height: u64,
    frontier: [u8; 32],
    entries: Vec<ActivityEntry>,
}
impl ActivityPage {
    /// Validate a contiguous page against the retained exact request.
    pub fn new(
        request: &ActivityRequest,
        tip: u64,
        height: u64,
        frontier: [u8; 32],
        entries: Vec<ActivityEntry>,
    ) -> Result<Self, ResponseError> {
        let ActivityKind::Page { after, count } = request.kind else {
            return Err(ResponseError::Request);
        };
        if after > tip
            || entries.len() > usize::from(count)
            || after
                .checked_add(entries.len() as u64)
                .is_none_or(|next| next > tip)
            || (entries.is_empty() && after < tip)
        {
            return Err(ResponseError::Bounds);
        }
        for (offset, entry) in entries.iter().enumerate() {
            if entry.cursor != after + offset as u64 + 1
                || entry.event.claims().scope.room.as_bytes() != &request.room
            {
                return Err(ResponseError::Request);
            }
        }
        Ok(Self {
            tip,
            height,
            frontier,
            entries,
        })
    }
    /// Last locally published cursor, not complete network history.
    pub const fn local_tip(&self) -> u64 {
        self.tip
    }
    /// Certified height locally observed for this response.
    pub const fn observed_height(&self) -> u64 {
        self.height
    }
    /// Complete locally observed certified frontier.
    pub const fn observed_frontier(&self) -> [u8; 32] {
        self.frontier
    }
    /// Bounded attributed events and local metadata.
    pub fn entries(&self) -> &[ActivityEntry] {
        &self.entries
    }
    /// Canonical bounded page body.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = PAGE_MAGIC.to_vec();
        out.extend_from_slice(&self.tip.to_be_bytes());
        out.extend_from_slice(&self.height.to_be_bytes());
        out.extend_from_slice(&self.frontier);
        out.push(self.entries.len() as u8);
        for entry in &self.entries {
            let event = entry.event.encode();
            out.extend_from_slice(&entry.cursor.to_be_bytes());
            out.extend_from_slice(&entry.registry);
            out.extend_from_slice(&(event.len() as u16).to_be_bytes());
            out.extend_from_slice(&event);
        }
        out
    }
    /// Decode strict event signatures and exact request/page framing. This does
    /// not establish historical policy authority, author-chain completeness or finality.
    pub fn decode(raw: &[u8], request: &ActivityRequest) -> Result<Self, ResponseError> {
        if raw.len() > MAX_ACTIVITY_PAGE_BYTES {
            return Err(ResponseError::Bounds);
        }
        let mut r = Reader(raw);
        if r.take(5)? != PAGE_MAGIC {
            return Err(ResponseError::Encoding);
        }
        let tip = r.u64()?;
        let height = r.u64()?;
        let frontier = r.array()?;
        let count = usize::from(r.take(1)?[0]);
        if count > MAX_ACTIVITY_PAGE {
            return Err(ResponseError::Bounds);
        }
        let mut entries = Vec::with_capacity(count);
        for _ in 0..count {
            let cursor = r.u64()?;
            let registry = r.array()?;
            let len = usize::from(u16::from_be_bytes(r.array()?));
            if len > MAX_EVENT_BYTES {
                return Err(ResponseError::Bounds);
            }
            let event = SignedEvent::decode(r.take(len)?)
                .map_err(|_| ResponseError::Encoding)?
                .verify()
                .map_err(|_| ResponseError::Signature)?;
            entries.push(ActivityEntry::new(cursor, registry, event)?);
        }
        r.end()?;
        Self::new(request, tip, height, frontier, entries)
    }
}

/// Typed successful activity response for a narrowly scoped custody signer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnsignedActivityResponse {
    network: [u8; 32],
    key: [u8; 32],
    request: ActivityRequest,
    hash: [u8; 32],
}
impl UnsignedActivityResponse {
    /// Validate bounded typed response framing and bind its exact body bytes.
    pub fn new(
        network: [u8; 32],
        key: [u8; 32],
        request: ActivityRequest,
        body: &[u8],
    ) -> Result<Self, ResponseError> {
        if network == [0; 32] {
            return Err(ResponseError::Network);
        }
        crate::checked_key(&key).map_err(|_| ResponseError::Peer)?;
        if body.len() > request.body_bound() {
            return Err(ResponseError::Bounds);
        }
        match request.kind {
            ActivityKind::Post { .. } => {
                if LocalReceipt::decode(body)?.room() != request.room {
                    return Err(ResponseError::Request);
                }
            }
            ActivityKind::Page { .. } => {
                let page = ActivityPage::decode(body, &request)?;
                if page
                    .entries
                    .iter()
                    .any(|entry| entry.event.claims().scope.network != network)
                {
                    return Err(ResponseError::Network);
                }
            }
        }
        Ok(Self {
            network,
            key,
            request,
            hash: Sha256::digest(body).into(),
        })
    }
    fn encode_unsigned(&self) -> Vec<u8> {
        let mut out = PROOF_MAGIC.to_vec();
        out.extend_from_slice(&self.network);
        out.extend_from_slice(&self.key);
        self.request.encode_into(&mut out);
        out.extend_from_slice(&self.hash);
        out
    }
    /// Domain-separated transcript for this typed response only.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut out = DOMAIN.to_vec();
        out.extend_from_slice(&self.encode_unsigned());
        out
    }
    /// Strictly attach a detached proof signature from the expected full peer key.
    pub fn attach_signature(
        self,
        signature: [u8; 64],
    ) -> Result<ActivityResponseProof, ResponseError> {
        let proof = ActivityResponseProof {
            statement: self,
            signature,
        };
        proof.check_signature()?;
        Ok(proof)
    }
    /// Sign using exactly the statement's full peer key; no generic message API.
    pub fn sign_with_key(self, key: &SigningKey) -> Result<ActivityResponseProof, ResponseError> {
        if key.verifying_key().to_bytes() != self.key {
            return Err(ResponseError::Peer);
        }
        let signature = key.sign(&self.signing_bytes()).to_bytes();
        self.attach_signature(signature)
    }
}
/// Peer-authenticated response; not a consensus activity certificate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActivityResponseProof {
    statement: UnsignedActivityResponse,
    signature: [u8; 64],
}
impl ActivityResponseProof {
    /// Encode the exact proof for the x-vhalla-proof response header.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.statement.encode_unsigned();
        out.extend_from_slice(&self.signature);
        out
    }
    /// Decode bounded proof claims, without verifying peer identity or signature.
    pub fn decode(raw: &[u8]) -> Result<Self, ResponseError> {
        if raw.len() > MAX_ACTIVITY_PROOF_BYTES {
            return Err(ResponseError::Bounds);
        }
        let mut r = Reader(raw);
        if r.take(5)? != PROOF_MAGIC {
            return Err(ResponseError::Encoding);
        }
        let statement = UnsignedActivityResponse {
            network: r.array()?,
            key: r.array()?,
            request: ActivityRequest::decode(&mut r)?,
            hash: r.array()?,
        };
        let signature = r.array()?;
        r.end()?;
        Ok(Self {
            statement,
            signature,
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
    /// Authenticate network, full peer, nonce, exact operation and complete body.
    /// Caller must separately interpret local durability and signed author history.
    pub fn verify(
        &self,
        network: [u8; 32],
        peer: [u8; 32],
        request: &ActivityRequest,
        body: &[u8],
    ) -> Result<(), ResponseError> {
        if self.statement.network != network {
            return Err(ResponseError::Network);
        }
        if self.statement.key != peer {
            return Err(ResponseError::Peer);
        }
        if self.statement.request.nonce != request.nonce {
            return Err(ResponseError::Nonce);
        }
        if self.statement.request != *request {
            return Err(ResponseError::Request);
        }
        let typed = UnsignedActivityResponse::new(network, peer, *request, body)?;
        if typed.hash != self.statement.hash {
            return Err(ResponseError::Body);
        }
        self.check_signature()
    }
}
/// Decode only bounded lowercase canonical hex proof headers.
pub fn proof_from_hex(raw: &str) -> Result<ActivityResponseProof, ResponseError> {
    if raw.len() > MAX_ACTIVITY_PROOF_BYTES * 2 || !raw.len().is_multiple_of(2) {
        return Err(ResponseError::Bounds);
    }
    let mut out = Vec::with_capacity(raw.len() / 2);
    for pair in raw.as_bytes().chunks_exact(2) {
        out.push(nibble(pair[0])? * 16 + nibble(pair[1])?);
    }
    ActivityResponseProof::decode(&out)
}
fn unhex32(raw: &str) -> Result<[u8; 32], ResponseError> {
    if raw.len() != 64 {
        return Err(ResponseError::Encoding);
    }
    let mut out = [0; 32];
    for (slot, pair) in out.iter_mut().zip(raw.as_bytes().chunks_exact(2)) {
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
    fn take(&mut self, n: usize) -> Result<&'a [u8], ResponseError> {
        let out = self.0.get(..n).ok_or(ResponseError::Encoding)?;
        self.0 = &self.0[n..];
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
    fn end(self) -> Result<(), ResponseError> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(ResponseError::Encoding)
        }
    }
}

#[cfg(test)]
mod tests;
