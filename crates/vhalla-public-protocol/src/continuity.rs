//! Bounded public continuity transport claims, not admission or delivery authority.
//!
//! Signature verification attributes event bytes. Historical policy checks and
//! current terminal admission require the independently certified registry core.
//! Temporary stage acknowledgements never advance a durable delivery floor.
//! This codec performs no I/O, timing, entropy generation, or state mutation.
pub use crate::response::ResponseError as Error;
use alloc::{boxed::Box, format, string::String, vec::Vec};
use ed25519_dalek::{Signature, Signer, SigningKey};
use sha2::{Digest, Sha256};
pub use vhalla_room_activity::continuity::EvidenceRole;
use vhalla_room_activity::{EventId, RoomScope, SignedEvent, VerifiedEvent, MAX_EVENT_BYTES};

mod reply;
mod request;
pub use reply::{
    Entry, EvidencePage, FeedPage, Observed, Reply, StageAck, Status, TerminalReceipt,
};
pub use request::{Body, Kind, Request, RequestContext, Selection};

/// Fixed temporary stage size; smaller suffixes go inline with a terminal.
pub const STAGE_EVENTS: usize = 32;
/// Maximum count in either bounded read page.
pub const MAX_PAGE: usize = 32;
/// Canonical request envelope ceiling, checked before allocating.
pub const MAX_REQUEST_BYTES: usize = 600;
/// Exact fixed origin prefix plus bounded lowercase request frame.
pub const MAX_TARGET_BYTES: usize = 30 + MAX_REQUEST_BYTES * 2;
/// Maximum request body: 32 history frames and one terminal.
pub const MAX_BODY_BYTES: usize = 6 + 33 * (2 + MAX_EVENT_BYTES);
/// Maximum reply, including 32 explicit role-tagged signed records.
pub const MAX_REPLY_BYTES: usize = 256 + 32 * (1 + 8 + 32 + 2 + MAX_EVENT_BYTES);
/// Maximum canonical signed response proof.
pub const MAX_PROOF_BYTES: usize = 5 + 32 + 2 + MAX_REQUEST_BYTES + 32 + 64;
const PROOF_DOMAIN: &[u8] = b"vhalla/public-continuity-response/v1\0";
const TARGET: &str = "/vhalla/v1/continuity?request=";

/// Exact public scope. These complete bytes never grant room authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Scope {
    /// Independently pinned stable network ID.
    pub network: [u8; 32],
    /// Complete big-endian realm ID.
    pub realm: [u8; 16],
    /// Complete directory commitment.
    pub directory: [u8; 32],
    /// Complete immutable room genesis.
    pub room: [u8; 32],
}
impl From<RoomScope> for Scope {
    fn from(s: RoomScope) -> Self {
        Self {
            network: s.network,
            realm: s.realm.0.to_be_bytes(),
            directory: *s.directory.as_bytes(),
            room: *s.room.as_bytes(),
        }
    }
}
impl Scope {
    fn check(self) -> Result<(), Error> {
        if self.network == [0; 32] {
            Err(Error::Network)
        } else {
            Ok(())
        }
    }
    fn put(self, out: &mut Vec<u8>) {
        out.extend(self.network);
        out.extend(self.realm);
        out.extend(self.directory);
        out.extend(self.room);
    }
    fn read(r: &mut Reader<'_>) -> Result<Self, Error> {
        let s = Self {
            network: r.array()?,
            realm: r.array()?,
            directory: r.array()?,
            room: r.array()?,
        };
        s.check()?;
        Ok(s)
    }
}
/// Exact known author-chain point; the empty sentinel has zero sequence AND ID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Position {
    sequence: u64,
    event: EventId,
}
impl Position {
    /// The complete never-published author base.
    pub const EMPTY: Self = Self {
        sequence: 0,
        event: EventId::ZERO,
    };
    /// Construct a structurally consistent position, without proving history.
    pub fn new(sequence: u64, event: EventId) -> Result<Self, Error> {
        if (sequence == 0) != (event == EventId::ZERO) {
            return Err(Error::Encoding);
        }
        Ok(Self { sequence, event })
    }
    /// Position attributed by a strictly verified signed event.
    pub fn of(event: &VerifiedEvent) -> Self {
        Self {
            sequence: event.claims().sequence,
            event: event.id(),
        }
    }
    /// Full author sequence.
    pub const fn sequence(self) -> u64 {
        self.sequence
    }
    /// Exact content ID, zero only at the empty base.
    pub const fn event_id(self) -> EventId {
        self.event
    }
    fn put(self, out: &mut Vec<u8>) {
        out.extend(self.sequence.to_be_bytes());
        out.extend(self.event.as_bytes());
    }
    fn read(r: &mut Reader<'_>) -> Result<Self, Error> {
        Self::new(r.u64()?, EventId::from_bytes(r.array()?))
    }
    fn extension(self, event: &VerifiedEvent) -> Result<Self, Error> {
        if self.sequence.checked_add(1) != Some(event.claims().sequence)
            || self.event != event.claims().previous
        {
            return Err(Error::Request);
        }
        Ok(Self::of(event))
    }
}
/// Exact remote temporary position. Its presence is not proof of persistence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StageRef {
    id: [u8; 32],
    tail: Position,
    pages: u32,
    expires: u64,
}
impl StageRef {
    /// Validate shape and exact page-count relation to the published base.
    pub fn new(
        id: [u8; 32],
        base: Position,
        tail: Position,
        pages: u32,
        expires: u64,
    ) -> Result<Self, Error> {
        if id == [0; 32]
            || pages == 0
            || pages > 128
            || expires == 0
            || base.sequence.checked_add(u64::from(pages) * 32) != Some(tail.sequence)
        {
            return Err(Error::Bounds);
        }
        Ok(Self {
            id,
            tail,
            pages,
            expires,
        })
    }
    /// Exact remote stage identifier; never an author capability.
    pub const fn id(self) -> [u8; 32] {
        self.id
    }
    /// Last staged point; not a published author floor.
    pub const fn tail(self) -> Position {
        self.tail
    }
    /// Fixed 32-event page count under this stage's published base.
    pub const fn pages(self) -> u32 {
        self.pages
    }
    /// Exclusive fixed lease expiry; retries cannot renew it.
    pub const fn expires_at(self) -> u64 {
        self.expires
    }
    fn check(self, base: Position) -> Result<(), Error> {
        Self::new(self.id, base, self.tail, self.pages, self.expires).map(|_| ())
    }
    fn put(self, out: &mut Vec<u8>) {
        out.extend(self.id);
        self.tail.put(out);
        out.extend(self.pages.to_be_bytes());
        out.extend(self.expires.to_be_bytes());
    }
    fn read(r: &mut Reader<'_>, base: Position) -> Result<Self, Error> {
        Self::new(r.array()?, base, Position::read(r)?, r.u32()?, r.u64()?)
    }
}

fn identity(event: &VerifiedEvent, scope: Scope, author: Option<[u8; 32]>) -> Result<(), Error> {
    if Scope::from(event.claims().scope) != scope
        || author.is_some_and(|a| a != event.claims().author)
    {
        return Err(Error::Request);
    }
    Ok(())
}
fn event_put(event: &VerifiedEvent, out: &mut Vec<u8>) {
    let raw = event.encode();
    out.extend((raw.len() as u16).to_be_bytes());
    out.extend(raw);
}
fn event_read(r: &mut Reader<'_>) -> Result<VerifiedEvent, Error> {
    let size = usize::from(r.u16()?);
    if size > MAX_EVENT_BYTES {
        return Err(Error::Bounds);
    }
    SignedEvent::decode(r.take(size)?)
        .map_err(|_| Error::Encoding)?
        .verify()
        .map_err(|_| Error::Signature)
}
fn stage_put(stage: Option<StageRef>, out: &mut Vec<u8>) {
    if let Some(stage) = stage {
        out.push(1);
        stage.put(out);
    } else {
        out.push(0);
    }
}
fn stage_read(r: &mut Reader<'_>, base: Position) -> Result<Option<StageRef>, Error> {
    match r.byte()? {
        0 => Ok(None),
        1 => Ok(Some(StageRef::read(r, base)?)),
        _ => Err(Error::Encoding),
    }
}
fn hash(raw: &[u8]) -> [u8; 32] {
    Sha256::digest(raw).into()
}
fn unhex(raw: &str, limit: usize) -> Result<Vec<u8>, Error> {
    if raw.len() > limit * 2 || !raw.len().is_multiple_of(2) {
        return Err(Error::Bounds);
    }
    let mut out = Vec::with_capacity(raw.len() / 2);
    for pair in raw.as_bytes().as_chunks::<2>().0 {
        fn nibble(v: u8) -> Result<u8, Error> {
            match v {
                b'0'..=b'9' => Ok(v - b'0'),
                b'a'..=b'f' => Ok(v - b'a' + 10),
                _ => Err(Error::Encoding),
            }
        }
        out.push(nibble(pair[0])? * 16 + nibble(pair[1])?);
    }
    Ok(out)
}
struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn framed(raw: &'a [u8], magic: &[u8], max: usize) -> Result<Self, Error> {
        if raw.len() > max {
            return Err(Error::Bounds);
        }
        let mut r = Self(raw);
        if r.take(magic.len())? != magic {
            return Err(Error::Encoding);
        }
        Ok(r)
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let a = self.0.get(..n).ok_or(Error::Encoding)?;
        self.0 = &self.0[n..];
        Ok(a)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        self.take(N)?.try_into().map_err(|_| Error::Encoding)
    }
    fn byte(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, Error> {
        Ok(u16::from_be_bytes(self.array()?))
    }
    fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_be_bytes(self.array()?))
    }
    fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    fn end(self) -> Result<(), Error> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(Error::Encoding)
        }
    }
}

/// Narrow typed response signing request; never signs arbitrary unframed bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnsignedResponse {
    peer: [u8; 32],
    request: Request,
    body: [u8; 32],
}
impl UnsignedResponse {
    /// Check canonical reply semantics and bind exact response/request bytes.
    pub fn new(peer: [u8; 32], request: Request, body: &[u8]) -> Result<Self, Error> {
        crate::checked_key(&peer).map_err(|_| Error::Peer)?;
        Reply::decode(body, &request)?;
        Ok(Self {
            peer,
            request,
            body: hash(body),
        })
    }
    fn unsigned(&self) -> Vec<u8> {
        let mut out = b"VHCP\x01".to_vec();
        out.extend(self.peer);
        let r = self.request.encode();
        out.extend((r.len() as u16).to_be_bytes());
        out.extend(r);
        out.extend(self.body);
        out
    }
    /// Domain-separated transcript only for this checked response.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut out = PROOF_DOMAIN.to_vec();
        out.extend(self.unsigned());
        out
    }
    /// Attach and strictly verify the exact expected peer's signature.
    pub fn attach_signature(self, signature: [u8; 64]) -> Result<ResponseProof, Error> {
        let p = ResponseProof {
            statement: self,
            signature,
        };
        p.signature()?;
        Ok(p)
    }
    /// Sign with exactly the selected application key; no generic signer API.
    pub fn sign_with_key(self, key: &SigningKey) -> Result<ResponseProof, Error> {
        if key.verifying_key().to_bytes() != self.peer {
            return Err(Error::Peer);
        }
        let signature = key.sign(&self.signing_bytes()).to_bytes();
        self.attach_signature(signature)
    }
}
/// A decoded peer assertion. Only verify returns authenticated response content.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResponseProof {
    statement: UnsignedResponse,
    signature: [u8; 64],
}
impl ResponseProof {
    /// Canonical proof suitable for a bounded lowercase-hex HTTP header.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.statement.unsigned();
        out.extend(self.signature);
        out
    }
    /// Bound and decode without accepting any signature or peer authority.
    pub fn decode(raw: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::framed(raw, b"VHCP\x01", MAX_PROOF_BYTES)?;
        let peer = r.array()?;
        crate::checked_key(&peer).map_err(|_| Error::Peer)?;
        let n = usize::from(r.u16()?);
        if n > MAX_REQUEST_BYTES {
            return Err(Error::Bounds);
        }
        let request = Request::decode(r.take(n)?)?;
        let body = r.array()?;
        let signature = r.array()?;
        r.end()?;
        Ok(Self {
            statement: UnsignedResponse {
                peer,
                request,
                body,
            },
            signature,
        })
    }
    /// Decode only lowercase canonical hex in a bounded proof header.
    pub fn from_hex(raw: &str) -> Result<Self, Error> {
        Self::decode(&unhex(raw, MAX_PROOF_BYTES)?)
    }
    fn signature(&self) -> Result<(), Error> {
        crate::checked_key(&self.statement.peer)
            .map_err(|_| Error::Peer)?
            .verify_strict(
                &self.statement.signing_bytes(),
                &Signature::from_bytes(&self.signature),
            )
            .map_err(|_| Error::Signature)
    }
    /// Authenticate exact selected peer/request/nonce/scope/floor and typed body.
    /// This does not establish registry certification, latest policy, complete
    /// prefix retention, network delivery or receipt-installation permission.
    pub fn verify(
        &self,
        peer: [u8; 32],
        request: &Request,
        body: &[u8],
    ) -> Result<VerifiedResponse, Error> {
        if peer != self.statement.peer {
            return Err(Error::Peer);
        }
        if request != &self.statement.request {
            return Err(Error::Request);
        }
        if body.len() > MAX_REPLY_BYTES {
            return Err(Error::Bounds);
        }
        if hash(body) != self.statement.body {
            return Err(Error::Body);
        }
        self.signature()?;
        Ok(VerifiedResponse {
            peer,
            request: *request,
            reply: Reply::decode(body, request)?,
        })
    }
}
/// Authenticated local peer statement, with no public construction shortcut.
pub struct VerifiedResponse {
    peer: [u8; 32],
    request: Request,
    reply: Reply,
}
impl VerifiedResponse {
    /// Exact receiving peer's complete application key.
    pub const fn peer(&self) -> [u8; 32] {
        self.peer
    }
    /// Exact request retained before the exchange.
    pub const fn request(&self) -> Request {
        self.request
    }
    /// Role-separated local claims. Their semantic limits remain applicable.
    pub fn reply(&self) -> &Reply {
        &self.reply
    }
}
#[cfg(test)]
mod tests;
