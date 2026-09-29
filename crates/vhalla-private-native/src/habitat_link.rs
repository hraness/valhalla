//! Bounded Habitat Link framing for a native Iroh profile.
//!
//! The frame carries one canonical JSON Habitat Link envelope. This module is
//! deliberately transport-only: it authenticates an Iroh endpoint and adds an
//! ALPN, but it does not grant mailbox authority, schedule work, or claim
//! exactly-once effects. Those semantics remain in the habitat protocol. The
//! existing private-room mailbox listener advertises this ALPN only when a
//! caller hands it a [`HabitatLinkService`] through
//! `Service::serve_iroh_with_habitat_link_until`. The default listener remains
//! unchanged; the CLI enables it only with an explicit socket bridge option.

#![cfg(feature = "habitat-link")]

mod service;
#[cfg(unix)]
mod socket;
#[cfg(unix)]
pub use socket::UnixHabitatLinkHandler;
#[cfg(test)]
mod service_tests;

pub use service::{
    endpoint_builder, send_envelope, send_envelope_until, HabitatLinkHandler, HabitatLinkService,
    CLIENT_EXCHANGE_TIMEOUT, CLOSE_CAPACITY, CLOSE_WRONG_ALPN, FRAME_READ_TIMEOUT,
    HANDSHAKE_TIMEOUT, MAX_CONNECTIONS_PER_SERVICE, MAX_STREAMS_PER_CONNECTION,
    MAX_STREAMS_PER_SERVICE, REPLY_WRITE_TIMEOUT, RESET_HANDLER, STOP_CAPACITY,
    STOP_FRAME_REJECTED, STOP_TIMEOUT, STREAM_IDLE_TIMEOUT,
};
use std::convert::TryFrom;

/// Iroh ALPN negotiated only by an explicitly enabled Habitat Link service.
pub const HABITAT_LINK_ALPN: &[u8] = b"algal/habitat/1";
/// Maximum encoded JSON envelope accepted by the adapter.
pub const MAX_FRAME_BYTES: usize = 262_144;
/// Maximum nested JSON container depth accepted by the adapter.
pub const MAX_JSON_DEPTH: usize = 64;

/// Errors returned before any envelope reaches a habitat scheduler.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum HabitatLinkError {
    /// A zero-length frame was supplied.
    Empty,
    /// The length prefix exceeds the protocol bound.
    Oversize,
    /// The frame ended before the declared payload.
    Truncated,
    /// More than one frame was supplied to the single-frame decoder.
    TrailingBytes,
    /// The envelope was not UTF-8.
    InvalidUtf8,
    /// The envelope was not valid JSON.
    InvalidJson,
    /// The JSON value was not a bounded object.
    InvalidEnvelope,
    /// The record contract is not part of Habitat Link v1.
    UnsupportedContract,
    /// The operation or message id was not lowercase 32-hex.
    InvalidOperationId,
    /// The connection negotiated an ALPN other than [`HABITAT_LINK_ALPN`].
    WrongAlpn,
    /// The connection or stream failed before the exchange completed.
    Connection,
    /// A handshake, read, write, or whole exchange exceeded its bound.
    Timeout,
    /// The habitat handler refused the envelope or failed while processing it.
    Handler,
}

/// Verify a single bounded canonical-JSON frame and prepend its network-order
/// length. `encode_frame` does not canonicalize the value; callers must use
/// the Habitat Link canonical serializer before this boundary.
pub fn encode_frame(envelope: &[u8]) -> Result<Vec<u8>, HabitatLinkError> {
    validate_envelope(envelope)?;
    let len = u32::try_from(envelope.len()).map_err(|_| HabitatLinkError::Oversize)?;
    if envelope.len() > MAX_FRAME_BYTES {
        return Err(HabitatLinkError::Oversize);
    }
    let mut frame = Vec::with_capacity(4 + envelope.len());
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(envelope);
    Ok(frame)
}

/// Decode exactly one complete frame. QUIC stream callers can retain the
/// remaining bytes and call this again; accepting trailing bytes here would
/// make message boundaries ambiguous.
pub fn decode_frame(frame: &[u8]) -> Result<Vec<u8>, HabitatLinkError> {
    if frame.len() < 4 {
        return Err(HabitatLinkError::Truncated);
    }
    let len = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]) as usize;
    if len == 0 {
        return Err(HabitatLinkError::Empty);
    }
    if len > MAX_FRAME_BYTES {
        return Err(HabitatLinkError::Oversize);
    }
    if frame.len() < len + 4 {
        return Err(HabitatLinkError::Truncated);
    }
    if frame.len() != len + 4 {
        return Err(HabitatLinkError::TrailingBytes);
    }
    validate_envelope(&frame[4..])?;
    Ok(frame[4..].to_vec())
}

/// A small explicit opt-in for adding Habitat Link to an existing Iroh ALPN
/// list. Private-room listeners call this only when they create a Habitat Link
/// service; the default list is unchanged.
pub fn with_habitat_link_alpn(mut alpns: Vec<Vec<u8>>, enabled: bool) -> Vec<Vec<u8>> {
    if enabled
        && !alpns
            .iter()
            .any(|alpn| alpn.as_slice() == HABITAT_LINK_ALPN)
    {
        alpns.push(HABITAT_LINK_ALPN.to_vec());
    }
    alpns
}

#[cfg(feature = "relay-iroh")]
/// Set a caller-owned Iroh endpoint's ALPN list with optional Habitat Link.
pub fn configure_iroh_endpoint(
    endpoint: &::iroh::Endpoint,
    private_room_alpns: Vec<Vec<u8>>,
    enabled: bool,
) {
    endpoint.set_alpns(with_habitat_link_alpn(private_room_alpns, enabled));
}

fn validate_envelope(bytes: &[u8]) -> Result<(), HabitatLinkError> {
    let text = std::str::from_utf8(bytes).map_err(|_| HabitatLinkError::InvalidUtf8)?;
    let value: serde_json::Value =
        serde_json::from_str(text).map_err(|_| HabitatLinkError::InvalidJson)?;
    if !value.is_object() || depth(&value, 0) > MAX_JSON_DEPTH {
        return Err(HabitatLinkError::InvalidEnvelope);
    }
    let contract = value
        .get("contract")
        .and_then(serde_json::Value::as_str)
        .ok_or(HabitatLinkError::InvalidEnvelope)?;
    if !matches!(
        contract,
        "algal.habitat-descriptor.v1"
            | "algal.habitat-invocation.v1"
            | "algal.habitat-acceptance.v1"
            | "algal.habitat-result.v1"
            | "algal.habitat-message.v1"
            | "algal.habitat-query.v1"
            | "algal.habitat-message-acceptance.v1"
    ) {
        return Err(HabitatLinkError::UnsupportedContract);
    }
    if let Some(id) = value.get("operationId").or_else(|| value.get("messageId")) {
        let id = id.as_str().ok_or(HabitatLinkError::InvalidOperationId)?;
        if id.len() != 32
            || !id
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(HabitatLinkError::InvalidOperationId);
        }
    }
    Ok(())
}

fn depth(value: &serde_json::Value, current: usize) -> usize {
    match value {
        serde_json::Value::Array(items) => items
            .iter()
            .map(|item| depth(item, current + 1))
            .max()
            .unwrap_or(current),
        serde_json::Value::Object(items) => items
            .values()
            .map(|item| depth(item, current + 1))
            .max()
            .unwrap_or(current),
        _ => current,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn invocation() -> Vec<u8> {
        br#"{"contract":"algal.habitat-invocation.v1","operationId":"0123456789abcdef0123456789abcdef"}"#.to_vec()
    }

    #[test]
    fn round_trip_and_opt_in_alpn() {
        let encoded = encode_frame(&invocation()).unwrap();
        assert_eq!(decode_frame(&encoded).unwrap(), invocation());
        assert_eq!(
            with_habitat_link_alpn(vec![b"private/1".to_vec()], false),
            vec![b"private/1".to_vec()]
        );
        assert_eq!(
            with_habitat_link_alpn(vec![b"private/1".to_vec()], true).len(),
            2
        );
        assert_eq!(HABITAT_LINK_ALPN, b"algal/habitat/1");
    }

    #[test]
    fn rejects_bounds_and_invalid_envelopes() {
        assert_eq!(decode_frame(&[0, 0, 0]), Err(HabitatLinkError::Truncated));
        assert_eq!(decode_frame(&[0, 0, 0, 0]), Err(HabitatLinkError::Empty));
        assert_eq!(
            decode_frame(&[0, 0, 0, 1, b'{']),
            Err(HabitatLinkError::InvalidJson)
        );
        let mut bad = encode_frame(&invocation()).unwrap();
        bad.push(0);
        assert_eq!(decode_frame(&bad), Err(HabitatLinkError::TrailingBytes));
        let mut unknown = invocation();
        unknown.splice(
            0..unknown.len(),
            br#"{"contract":"future.v9"}"#.iter().copied(),
        );
        assert_eq!(
            encode_frame(&unknown),
            Err(HabitatLinkError::UnsupportedContract)
        );
    }
}
