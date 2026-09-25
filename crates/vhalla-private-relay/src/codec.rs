//! Canonical relay v1 framing shared by native TLS and browser HTTP.
use crate::{
    Error, PositionedItem, RelayItem, RelayPage, RelayReceipt, MAGIC, MAX_RELAY_PAGE,
    MAX_RELAY_PAYLOAD,
};
use std::time::Duration;
/// Closed adapter failures. None carries ciphertext, tokens or addresses.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetError {
    /// The listener was unreachable or the connection failed.
    Connect,
    /// A bounded read, write or connect deadline elapsed.
    Timeout,
    /// The mailbox refused the presented token.
    Denied,
    /// The same sequence or operation arrived with different bytes.
    Conflict,
    /// The relay quota is full; retained items are never pruned.
    Capacity,
    /// Input or wire data was malformed, noncanonical or over a bound.
    Bounds,
    /// The item belongs to another opaque namespace.
    Scope,
    /// The peer answered with a noncanonical frame or status.
    Malformed,
    /// A durable or socket operation failed without a finer claim.
    Unavailable,
}
impl core::fmt::Display for NetError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for NetError {}
type NetResult<T> = std::result::Result<T, NetError>;
/// Maximum request body: token plus one canonical item frame.
pub const MAX_PUT_BODY: usize = 32 + MAGIC.len() + 32 + 8 + 16 + 1 + 4 + MAX_RELAY_PAYLOAD + 32;
/// Request length field bound; GET-style operations are far below this.
pub const MAX_REQUEST: usize = 1 + MAX_PUT_BODY;
/// Response budget for one page: metadata plus whole item frames. A page that
/// cannot fit returns `more` so the caller resumes at its retained cursor.
pub const MAX_PAGE_BODY: usize = 4 * 1024 * 1024;
/// Largest response frame: status byte plus a full page body.
pub const MAX_RESPONSE: usize = 1 + MAX_PAGE_BODY;
/// Canonical relay v1 op put tag.
pub const OP_PUT: u8 = 1;
/// Canonical relay v1 op page tag.
pub const OP_PAGE: u8 = 2;
/// Canonical relay v1 status ok tag.
pub const STATUS_OK: u8 = 0;
/// Canonical relay v1 status conflict tag.
pub const STATUS_CONFLICT: u8 = 2;
/// Canonical relay v1 status capacity tag.
pub const STATUS_CAPACITY: u8 = 3;
/// Canonical relay v1 status bounds tag.
pub const STATUS_BOUNDS: u8 = 4;
/// Canonical relay v1 status scope tag.
pub const STATUS_SCOPE: u8 = 5;
/// Canonical relay v1 status denied tag.
pub const STATUS_DENIED: u8 = 6;
/// Canonical relay v1 status unavailable tag.
pub const STATUS_UNAVAILABLE: u8 = 7;

/// Map a closed storage failure to its canonical status.
pub fn status(error: Error) -> u8 {
    match error {
        Error::Conflict => STATUS_CONFLICT,
        Error::Capacity => STATUS_CAPACITY,
        Error::Scope => STATUS_SCOPE,
        Error::Storage => STATUS_UNAVAILABLE,
        Error::Bounds | Error::Confidential => STATUS_BOUNDS,
    }
}
/// Reject noncanonical status bodies and decode a successful payload.
pub fn decode_status(code: u8, body: &[u8]) -> NetResult<Vec<u8>> {
    if code != STATUS_OK && !body.is_empty() {
        return Err(NetError::Malformed);
    }
    match code {
        STATUS_OK => Ok(body.to_vec()),
        STATUS_CONFLICT => Err(NetError::Conflict),
        STATUS_CAPACITY => Err(NetError::Capacity),
        STATUS_BOUNDS => Err(NetError::Bounds),
        STATUS_SCOPE => Err(NetError::Scope),
        STATUS_DENIED => Err(NetError::Denied),
        STATUS_UNAVAILABLE => Err(NetError::Unavailable),
        _ => Err(NetError::Malformed),
    }
}
/// Frame a bounded body; callers must enforce MAX_REQUEST or MAX_RESPONSE.
pub fn frame(op: u8, body: &[u8]) -> Vec<u8> {
    let len = u32::try_from(1 + body.len()).expect("bounded relay frame");
    let mut out = Vec::with_capacity(4 + len as usize);
    out.extend_from_slice(&len.to_be_bytes());
    out.push(op);
    out.extend_from_slice(body);
    out
}
/// Validate the immutable, contiguous mailbox page contract before any effects.
pub fn validate_page(page: &RelayPage, after: u64, limit: usize) -> NetResult<()> {
    if limit == 0 || limit > MAX_RELAY_PAGE || page.records.len() > limit {
        return Err(NetError::Malformed);
    }
    // A standalone fetch beyond the retained head is a valid absence. A scan
    // separately refuses this as a rollback of its already retained cursor.
    if page.head < after {
        return if page.records.is_empty() && page.next.is_none() {
            Ok(())
        } else {
            Err(NetError::Malformed)
        };
    }
    let mut previous = after;
    for record in &page.records {
        if Some(record.position) != previous.checked_add(1) || record.position > page.head {
            return Err(NetError::Malformed);
        }
        previous = record.position;
    }
    if (previous < page.head && (page.records.is_empty() || page.next != Some(previous)))
        || (previous == page.head && page.next.is_some())
    {
        return Err(NetError::Malformed);
    }
    Ok(())
}

/// Authenticate the exact retained digest and a nonzero mailbox position.
pub fn decode_receipt(body: &[u8], item: &RelayItem) -> NetResult<RelayReceipt> {
    if body.len() != 41 {
        return Err(NetError::Malformed);
    }
    let position = u64::from_be_bytes(body[..8].try_into().expect("bounded"));
    let digest: [u8; 32] = body[8..40].try_into().expect("bounded");
    if position == 0 || digest != item.digest() || body[40] > 1 {
        return Err(NetError::Malformed);
    }
    Ok(RelayReceipt {
        position,
        digest,
        duplicate: body[40] != 0,
    })
}
/// Encode a bounded page request without credentials.
pub fn page_request(after: u64, limit: usize) -> NetResult<Vec<u8>> {
    if !(1..=MAX_RELAY_PAGE).contains(&limit) {
        return Err(NetError::Bounds);
    }
    let mut request = after.to_be_bytes().to_vec();
    request.extend_from_slice(&(limit as u16).to_be_bytes());
    Ok(request)
}
/// Encode a page request the host may hold open up to `wait` before answering.
/// The extra two bytes make it a distinct request shape: a host that predates
/// bounded waits answers STATUS_BOUNDS and the caller falls back to polling.
/// The response is the same canonical page, empty on expiry.
pub fn page_wait_request(after: u64, limit: usize, wait: Duration) -> NetResult<Vec<u8>> {
    let wait_ms = u16::try_from(wait.as_millis()).map_err(|_| NetError::Bounds)?;
    let mut request = page_request(after, limit)?;
    request.extend_from_slice(&wait_ms.to_be_bytes());
    Ok(request)
}
/// Decode and validate one immutable contiguous mailbox page.
pub fn decode_page(body: &[u8], after: u64, limit: usize) -> NetResult<RelayPage> {
    if body.len() < 11 || body.len() > MAX_PAGE_BODY || !(1..=MAX_RELAY_PAGE).contains(&limit) {
        return Err(NetError::Malformed);
    }
    let head = u64::from_be_bytes(body[..8].try_into().expect("bounded"));
    let more = match body[8] {
        0 => false,
        1 => true,
        _ => return Err(NetError::Malformed),
    };
    let count = u16::from_be_bytes(body[9..11].try_into().expect("bounded")) as usize;
    if count > limit {
        return Err(NetError::Malformed);
    }
    let mut records = Vec::with_capacity(count);
    let mut cursor = 11usize;
    for _ in 0..count {
        let end = cursor.checked_add(8).ok_or(NetError::Malformed)?;
        if end > body.len() {
            return Err(NetError::Malformed);
        }
        let position = u64::from_be_bytes(body[cursor..end].try_into().expect("bounded"));
        if position == 0 {
            return Err(NetError::Malformed);
        }
        cursor = end;
        let end = cursor.checked_add(4).ok_or(NetError::Malformed)?;
        if end > body.len() {
            return Err(NetError::Malformed);
        }
        let len = u32::from_be_bytes(body[cursor..end].try_into().expect("bounded")) as usize;
        cursor = end;
        let end = cursor.checked_add(len).ok_or(NetError::Malformed)?;
        if end > body.len() {
            return Err(NetError::Malformed);
        }
        let item = RelayItem::decode(&body[cursor..end]).map_err(|_| NetError::Malformed)?;
        records.push(PositionedItem { position, item });
        cursor = end;
    }
    if cursor != body.len()
        || (more && records.is_empty())
        || !records
            .iter()
            .zip(records.iter().skip(1))
            .all(|(a, b)| a.position < b.position)
    {
        return Err(NetError::Malformed);
    }
    let next = more.then(|| records.last().expect("nonempty").position);
    let page = RelayPage {
        head,
        next,
        records,
    };
    validate_page(&page, after, limit)?;
    Ok(page)
}

/// Decode exactly one length-prefixed frame with no trailing bytes.
pub fn decode_frame(raw: &[u8], max: usize) -> NetResult<(u8, &[u8])> {
    if raw.len() < 5 || raw.len() > max.saturating_add(4) {
        return Err(NetError::Malformed);
    }
    let len = u32::from_be_bytes(raw[..4].try_into().expect("bounded")) as usize;
    if len == 0 || len != raw.len() - 4 {
        return Err(NetError::Malformed);
    }
    Ok((raw[4], &raw[5..]))
}
/// Encode one exact retention receipt, never member acceptance.
pub fn encode_receipt(receipt: RelayReceipt) -> Vec<u8> {
    let mut out = receipt.position.to_be_bytes().to_vec();
    out.extend_from_slice(&receipt.digest);
    out.push(u8::from(receipt.duplicate));
    out
}
/// Encode a bounded page, retaining a continuation when the byte cap truncates it.
pub fn encode_page(page: &RelayPage) -> NetResult<Vec<u8>> {
    if page.records.len() > MAX_RELAY_PAGE {
        return Err(NetError::Bounds);
    }
    let mut out = page.head.to_be_bytes().to_vec();
    let mut more = page.next.is_some();
    let mut count = 0u16;
    let mut items = Vec::new();
    for record in &page.records {
        let encoded = record.item.encode().map_err(|_| NetError::Unavailable)?;
        if 11 + items.len() + 12 + encoded.len() > MAX_PAGE_BODY && count > 0 {
            more = true;
            break;
        }
        items.extend_from_slice(&record.position.to_be_bytes());
        items.extend_from_slice(&(encoded.len() as u32).to_be_bytes());
        items.extend_from_slice(&encoded);
        count += 1;
    }
    out.push(u8::from(more));
    out.extend_from_slice(&count.to_be_bytes());
    out.extend_from_slice(&items);
    Ok(out)
}
