//! Retained authenticated evidence of one peer's local activity acceptance.
//! This never marks an event globally delivered or consensus committed.
use super::{AuthorScope, Reader};
use crate::Error;
use vhalla_public_protocol::activity::{
    ActivityKind, ActivityRequest, ActivityResponseProof, LocalReceipt, MAX_ACTIVITY_PROOF_BYTES,
    MAX_ACTIVITY_TARGET, RECEIPT_BYTES,
};
use vhalla_room_activity::{EventId, SignedEvent, VerifiedEvent};

const HEAD_MAGIC: &[u8; 8] = b"VHBDHD01";
const RECORD_MAGIC: &[u8; 8] = b"VHBDRC01";
pub(crate) const DELIVERY_HEAD_BYTES: usize = 264;
/// Maximum one retained request/proof/receipt record, checked before allocation.
pub const MAX_DELIVERY_RECORD_BYTES: usize =
    8 + DELIVERY_HEAD_BYTES + 6 + MAX_ACTIVITY_TARGET + MAX_ACTIVITY_PROOF_BYTES + RECEIPT_BYTES;

/// Contiguous author prefix acknowledged by one exact full peer key.
///
/// The corresponding retained response proof must be verified before trusting
/// this metadata. This floor says nothing about another peer or global delivery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeliveryHead {
    scope: AuthorScope,
    peer: [u8; 32],
    sequence: u64,
    event: EventId,
    cursor: u64,
    body_hash: [u8; 32],
}
impl DeliveryHead {
    /// Full room/network/directory/realm/author scope.
    #[must_use]
    pub const fn scope(self) -> AuthorScope {
        self.scope
    }
    /// Full response-signing peer key, never a route or shortened identifier.
    #[must_use]
    pub const fn peer(self) -> [u8; 32] {
        self.peer
    }
    /// Highest contiguous author sequence acknowledged by this peer.
    #[must_use]
    pub const fn sequence(self) -> u64 {
        self.sequence
    }
    /// Exact author-signed event at this floor.
    #[must_use]
    pub const fn event_id(self) -> EventId {
        self.event
    }
    /// This peer's local admission ordinal, not an author/global cursor.
    #[must_use]
    pub const fn local_cursor(self) -> u64 {
        self.cursor
    }
    /// SHA-256 of the complete signed local outbox bytes in the bound POST.
    #[must_use]
    pub const fn body_hash(self) -> [u8; 32] {
        self.body_hash
    }
    /// Canonical exact-CAS metadata; authenticate through its retained record.
    #[must_use]
    pub fn encode(self) -> Vec<u8> {
        let mut raw = Vec::with_capacity(DELIVERY_HEAD_BYTES);
        raw.extend_from_slice(HEAD_MAGIC);
        self.scope.encode(&mut raw);
        raw.extend_from_slice(&self.peer);
        raw.extend_from_slice(&self.sequence.to_be_bytes());
        raw.extend_from_slice(self.event.as_bytes());
        raw.extend_from_slice(&self.cursor.to_be_bytes());
        raw.extend_from_slice(&self.body_hash);
        raw
    }
    /// Decode framing only. This cannot substitute for response verification.
    pub fn decode(raw: &[u8]) -> Result<Self, Error> {
        if raw.len() != DELIVERY_HEAD_BYTES {
            return Err(Error::Corrupt);
        }
        let mut input = Reader(raw);
        if &input.array::<8>()? != HEAD_MAGIC {
            return Err(Error::Corrupt);
        }
        let scope = AuthorScope {
            network: input.array()?,
            realm: input.array()?,
            directory: input.array()?,
            room: input.array()?,
            author: input.array()?,
        };
        let value = Self {
            scope,
            peer: input.array()?,
            sequence: u64::from_be_bytes(input.array()?),
            event: EventId::from_bytes(input.array()?),
            cursor: u64::from_be_bytes(input.array()?),
            body_hash: input.array()?,
        };
        if value.sequence == 0 || value.cursor == 0 || value.event == EventId::ZERO {
            return Err(Error::Corrupt);
        }
        Ok(value)
    }
}

/// Canonical request plus strictly authenticated peer proof and exact receipt.
///
/// Construction authenticates the peer's statement. `check_event` must also
/// bind it to the actual complete signed outbox event before storage or use.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeliveryRecord {
    head: DeliveryHead,
    request: ActivityRequest,
    proof: ActivityResponseProof,
    receipt: LocalReceipt,
    bytes: Vec<u8>,
}
impl DeliveryRecord {
    /// Verify exact network, full peer, POST challenge/body and receipt identity.
    /// The challenge's original freshness remains the transport caller's duty.
    pub fn new(
        scope: AuthorScope,
        peer: [u8; 32],
        request: &ActivityRequest,
        proof: &ActivityResponseProof,
        receipt_bytes: &[u8],
    ) -> Result<Self, Error> {
        if receipt_bytes.len() != RECEIPT_BYTES {
            return Err(Error::Bounds);
        }
        let ActivityKind::Post { body_hash } = request.kind() else {
            return Err(Error::Corrupt);
        };
        proof
            .verify(scope.network(), peer, request, receipt_bytes)
            .map_err(|_| Error::Corrupt)?;
        let receipt = LocalReceipt::decode(receipt_bytes).map_err(|_| Error::Corrupt)?;
        if receipt.event_id() == EventId::ZERO {
            return Err(Error::Corrupt);
        }
        if request.room() != scope.room
            || receipt.room() != scope.room
            || receipt.author() != scope.author()
        {
            return Err(Error::WrongScope);
        }
        let head = DeliveryHead {
            scope,
            peer,
            sequence: receipt.sequence(),
            event: receipt.event_id(),
            cursor: receipt.local_cursor(),
            body_hash,
        };
        let target = request.target();
        let proof_bytes = proof.encode();
        let mut bytes = Vec::with_capacity(MAX_DELIVERY_RECORD_BYTES);
        bytes.extend_from_slice(RECORD_MAGIC);
        bytes.extend_from_slice(&head.encode());
        for part in [target.as_bytes(), proof_bytes.as_slice(), receipt_bytes] {
            bytes.extend_from_slice(&(part.len() as u16).to_be_bytes());
            bytes.extend_from_slice(part);
        }
        Ok(Self {
            head,
            request: *request,
            proof: proof.clone(),
            receipt,
            bytes,
        })
    }
    /// Decode canonical bounded framing and reverify the retained peer proof.
    /// Match `head().scope()` and `head().peer()` to the independently selected
    /// scope/key, then bind to the retained event with `check_event`.
    pub fn decode(raw: &[u8]) -> Result<Self, Error> {
        if raw.len() > MAX_DELIVERY_RECORD_BYTES {
            return Err(Error::Bounds);
        }
        let mut input = Reader(raw);
        if &input.array::<8>()? != RECORD_MAGIC {
            return Err(Error::Corrupt);
        }
        let head = DeliveryHead::decode(input.take(DELIVERY_HEAD_BYTES)?)?;
        let target = part(&mut input, MAX_ACTIVITY_TARGET)?;
        let target = std::str::from_utf8(target).map_err(|_| Error::Corrupt)?;
        let request = ActivityRequest::parse_target(target).map_err(|_| Error::Corrupt)?;
        let proof = ActivityResponseProof::decode(part(&mut input, MAX_ACTIVITY_PROOF_BYTES)?)
            .map_err(|_| Error::Corrupt)?;
        let receipt = part(&mut input, RECEIPT_BYTES)?;
        if !input.0.is_empty() {
            return Err(Error::Corrupt);
        }
        let record = Self::new(head.scope, head.peer, &request, &proof, receipt)?;
        if record.head != head || record.as_bytes() != raw {
            return Err(Error::Corrupt);
        }
        Ok(record)
    }
    /// Complete retained evidence bytes, including the original fresh challenge.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Authenticated peer-local delivery metadata; not global delivery.
    #[must_use]
    pub const fn head(&self) -> DeliveryHead {
        self.head
    }
    /// Exact POST request that this peer authenticated.
    #[must_use]
    pub const fn request(&self) -> &ActivityRequest {
        &self.request
    }
    /// Original authenticated peer response proof, retained without replacement.
    #[must_use]
    pub const fn proof(&self) -> &ActivityResponseProof {
        &self.proof
    }
    /// Original peer-local acceptance statement; observed frontier is not latest.
    #[must_use]
    pub const fn receipt(&self) -> &LocalReceipt {
        &self.receipt
    }
    /// Verify the full author signature, immutable scope, ID, sequence and exact
    /// POST byte hash against the actual retained signed local outbox record.
    pub fn check_event(&self, raw: &[u8]) -> Result<VerifiedEvent, Error> {
        self.request.check_body(raw).map_err(|_| Error::Corrupt)?;
        let event = SignedEvent::decode(raw)
            .and_then(SignedEvent::verify)
            .map_err(|_| Error::Corrupt)?;
        if AuthorScope::new(event.claims().scope, event.claims().author) != self.head.scope
            || event.id() != self.head.event
            || event.claims().sequence != self.head.sequence
        {
            return Err(Error::WrongScope);
        }
        Ok(event)
    }
}

fn part<'a>(input: &mut Reader<'a>, maximum: usize) -> Result<&'a [u8], Error> {
    let length = u16::from_be_bytes(input.array()?) as usize;
    if length > maximum {
        return Err(Error::Bounds);
    }
    input.take(length)
}

#[cfg(any(target_arch = "wasm32", test))]
pub(crate) fn prefix(scope: AuthorScope, peer: [u8; 32]) -> String {
    let peer = peer.iter().map(|b| format!("{b:02x}")).collect::<String>();
    format!("{}delivery/{peer}/", super::prefix(scope))
}

// True adds a new immutable receipt; false retains the already-acknowledged
// latest event's original proof/cursor, even if a retry reports a reset cursor.
#[cfg(any(target_arch = "wasm32", unix, test))]
pub(crate) fn advance(
    expected: Option<&DeliveryHead>,
    observed: Option<&DeliveryHead>,
    candidate: &DeliveryRecord,
    event: &VerifiedEvent,
) -> Result<bool, Error> {
    if expected != observed {
        return Err(Error::Stale);
    }
    if AuthorScope::new(event.claims().scope, event.claims().author) != candidate.head.scope
        || event.id() != candidate.head.event
        || event.claims().sequence != candidate.head.sequence
    {
        return Err(Error::WrongScope);
    }
    let (sequence, previous, cursor) = match observed {
        Some(head) => {
            if head.scope != candidate.head.scope || head.peer != candidate.head.peer {
                return Err(Error::WrongScope);
            }
            if candidate.head.sequence == head.sequence {
                return if head.event == candidate.head.event
                    && head.body_hash == candidate.head.body_hash
                {
                    Ok(false)
                } else {
                    Err(Error::Stale)
                };
            }
            (head.sequence, head.event, head.cursor)
        }
        None => (0, EventId::ZERO, 0),
    };
    if sequence.checked_add(1) != Some(candidate.head.sequence)
        || event.claims().previous != previous
        || candidate.head.cursor <= cursor
    {
        return Err(Error::Stale);
    }
    Ok(true)
}

#[cfg(test)]
mod tests;
