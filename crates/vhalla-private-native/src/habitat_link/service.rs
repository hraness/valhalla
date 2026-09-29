//! Dedicated Iroh handler and client for one-frame Habitat Link exchanges.
//!
//! Every request is one bidirectional QUIC stream carrying exactly one
//! [`encode_frame`] request and exactly one reply frame. The transport reads
//! the length prefix first and refuses an oversize declaration before any
//! payload byte is buffered, then hands the validated envelope bytes to the
//! habitat's [`HabitatLinkHandler`]. The transport never interprets the
//! envelope: acceptance, scheduling, replay identity and evidence stay in the
//! habitat.
//!
//! The Iroh endpoint key authenticates the peer's transport only. It grants no
//! habitat authority; the grant carried inside the envelope does.

use super::{decode_frame, encode_frame, HabitatLinkError, HABITAT_LINK_ALPN, MAX_FRAME_BYTES};
use ::iroh::endpoint::{
    presets, ConnectionError, QuicTransportConfig, ReadExactError, RecvStream, SendStream, VarInt,
};
use ::iroh::{Endpoint, EndpointAddr, RelayMap, RelayMode};
use std::{
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use tokio::task::JoinSet;

/// Live request streams one peer connection may hold at once. The private-room
/// listener's QUIC transport config additionally caps peer-opened
/// bidirectional streams at one.
pub const MAX_STREAMS_PER_CONNECTION: usize = 4;
/// Live request streams across every connection one service is handling.
/// Each live stream may occupy one blocking worker while the handler runs.
pub const MAX_STREAMS_PER_SERVICE: usize = 64;
/// Live peer connections one dedicated [`HabitatLinkService::serve`] loop
/// keeps at once; further handshakes are refused before they complete.
pub const MAX_CONNECTIONS_PER_SERVICE: usize = 32;
/// Bound on the QUIC/TLS handshake of an accepted connection.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(4);
/// Bound on reading one complete request frame after the stream opens.
pub const FRAME_READ_TIMEOUT: Duration = Duration::from_secs(10);
/// Bound on writing one reply frame and receiving the peer's acknowledgement.
pub const REPLY_WRITE_TIMEOUT: Duration = Duration::from_secs(10);
/// A connection with no new request stream for this long is closed.
pub const STREAM_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
/// Default bound on a whole client exchange: connect, send, reply.
pub const CLIENT_EXCHANGE_TIMEOUT: Duration = Duration::from_secs(25);

/// QUIC application close code when the negotiated ALPN is not Habitat Link.
pub const CLOSE_WRONG_ALPN: u32 = 1;
/// QUIC application close code when the connection budget is exhausted.
pub const CLOSE_CAPACITY: u32 = 2;
/// Stream stop/reset code when the request frame violates the framing bounds.
pub const STOP_FRAME_REJECTED: u32 = 2;
/// Stream stop/reset code when the stream budget is exhausted.
pub const STOP_CAPACITY: u32 = 3;
/// Stream stop/reset code when the request read exceeded its deadline.
pub const STOP_TIMEOUT: u32 = 4;
/// Stream reset code when the habitat handler refused the envelope.
pub const RESET_HANDLER: u32 = 5;

/// Habitat-owned envelope processing. The transport passes validated envelope
/// bytes and expects one canonical-JSON reply envelope that passes the same
/// frame contract. Errors close the stream without a reply frame.
///
/// The handler runs on a bounded blocking worker; it may block, but a panic
/// inside it is reported to the peer as a reset and to the service as
/// [`HabitatLinkError::Handler`], not propagated. The transport bounds the
/// handshake, the request read, connection idleness and the reply write; the
/// handler's own running time is the habitat's bound, and its stream slot
/// stays held until it returns.
pub trait HabitatLinkHandler: Send + Sync + 'static {
    /// Process one envelope and return the reply envelope bytes.
    fn handle(&self, envelope: &[u8]) -> Result<Vec<u8>, HabitatLinkError>;
}

impl<F> HabitatLinkHandler for F
where
    F: Fn(&[u8]) -> Result<Vec<u8>, HabitatLinkError> + Send + Sync + 'static,
{
    fn handle(&self, envelope: &[u8]) -> Result<Vec<u8>, HabitatLinkError> {
        self(envelope)
    }
}

/// Opt-in Habitat Link request service for connections negotiated on
/// [`HABITAT_LINK_ALPN`].
///
/// A service is only constructed by a caller that explicitly enables Habitat
/// Link; no listener advertises the ALPN otherwise. Endpoint identity is
/// transport authentication only and grants no habitat authority.
#[derive(Clone)]
pub struct HabitatLinkService {
    handler: Arc<dyn HabitatLinkHandler>,
    streams: Arc<AtomicUsize>,
}

struct Budget {
    counter: Arc<AtomicUsize>,
}

impl Budget {
    fn reserve(counter: &Arc<AtomicUsize>, max: usize) -> Option<Self> {
        let mut current = counter.load(Ordering::Acquire);
        loop {
            if current >= max {
                return None;
            }
            match counter.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Some(Self {
                        counter: counter.clone(),
                    })
                }
                Err(observed) => current = observed,
            }
        }
    }
}

impl Drop for Budget {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Bounded Iroh endpoint configuration for a dedicated Habitat Link endpoint:
/// no public discovery, no datagrams, no unidirectional streams, at most
/// [`MAX_STREAMS_PER_CONNECTION`] peer-opened bidirectional streams, and an
/// explicit HTTPS relay only when one is given. The caller sets the secret
/// key and bind address and calls `bind`.
pub fn endpoint_builder(
    relay_url: Option<&str>,
) -> Result<::iroh::endpoint::Builder, HabitatLinkError> {
    let streams =
        u32::try_from(MAX_STREAMS_PER_CONNECTION).map_err(|_| HabitatLinkError::Oversize)?;
    let window = u32::try_from(MAX_FRAME_BYTES + 4).map_err(|_| HabitatLinkError::Oversize)?;
    let transport = QuicTransportConfig::builder()
        .max_concurrent_bidi_streams(streams.into())
        .max_concurrent_uni_streams(0u32.into())
        .stream_receive_window(window.into())
        .receive_window(window.saturating_mul(streams).into())
        .send_window(u64::from(window) * u64::from(streams))
        .datagram_receive_buffer_size(None)
        .datagram_send_buffer_size(0)
        .build();
    let mut builder = Endpoint::builder(presets::Minimal).transport_config(transport);
    if let Some(relay) = relay_url {
        let relay =
            crate::relay::iroh::checked_relay(relay).map_err(|_| HabitatLinkError::Connection)?;
        builder = builder.relay_mode(RelayMode::Custom(RelayMap::from_iter([relay])));
    }
    Ok(builder)
}

impl HabitatLinkService {
    /// Wrap a habitat handler. Nothing is bound or advertised by construction.
    pub fn new(handler: impl HabitatLinkHandler) -> Self {
        Self {
            handler: Arc::new(handler),
            streams: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Live request streams currently held across every connection.
    pub fn live_streams(&self) -> usize {
        self.streams.load(Ordering::Acquire)
    }

    /// Serve one completed connection. A connection that did not negotiate
    /// [`HABITAT_LINK_ALPN`] is closed with [`CLOSE_WRONG_ALPN`] and never
    /// reaches the handler. Returns the number of request streams that
    /// received a reply frame once the peer closes or goes idle.
    pub async fn serve_connection(
        &self,
        connection: ::iroh::endpoint::Connection,
    ) -> Result<usize, HabitatLinkError> {
        if connection.alpn() != HABITAT_LINK_ALPN {
            connection.close(VarInt::from_u32(CLOSE_WRONG_ALPN), b"alpn");
            return Err(HabitatLinkError::WrongAlpn);
        }
        let per_connection = Arc::new(AtomicUsize::new(0));
        let mut tasks: JoinSet<bool> = JoinSet::new();
        let mut replied = 0usize;
        let outcome = loop {
            let accepted = tokio::select! {
                accepted = tokio::time::timeout(STREAM_IDLE_TIMEOUT, connection.accept_bi()) => accepted,
                Some(joined) = tasks.join_next() => {
                    if joined.unwrap_or(false) {
                        replied += 1;
                    }
                    continue;
                }
            };
            let (send, recv) = match accepted {
                Ok(Ok(stream)) => stream,
                Ok(Err(ConnectionError::ApplicationClosed(_)))
                | Ok(Err(ConnectionError::LocallyClosed)) => break Ok(()),
                Ok(Err(_)) => break Err(HabitatLinkError::Connection),
                Err(_) => break Err(HabitatLinkError::Timeout),
            };
            let (Some(connection_slot), Some(service_slot)) = (
                Budget::reserve(&per_connection, MAX_STREAMS_PER_CONNECTION),
                Budget::reserve(&self.streams, MAX_STREAMS_PER_SERVICE),
            ) else {
                stop_stream(send, recv, STOP_CAPACITY);
                continue;
            };
            let handler = self.handler.clone();
            tasks.spawn(async move {
                let _slots = (connection_slot, service_slot);
                serve_stream(handler, send, recv).await.is_ok()
            });
        };
        // Every live stream is bounded by its own read and reply deadlines.
        while let Some(joined) = tasks.join_next().await {
            if joined.unwrap_or(false) {
                replied += 1;
            }
        }
        connection.close(VarInt::from_u32(0), b"done");
        outcome.map(|()| replied)
    }

    /// Accept loop for an endpoint dedicated to Habitat Link. It returns when
    /// `stop` is set or the endpoint closes. Shutdown is bounded: the ALPN is
    /// withdrawn and live connections are aborted rather than drained, so a
    /// request without a reply frame is retried by operation identity, not
    /// by this transport. Per-connection failures are contained; the loop
    /// only reports its own shutdown outcome.
    pub async fn serve(
        &self,
        endpoint: &Endpoint,
        stop: Arc<AtomicBool>,
    ) -> Result<(), HabitatLinkError> {
        endpoint.set_alpns(vec![HABITAT_LINK_ALPN.to_vec()]);
        let connections = Arc::new(AtomicUsize::new(0));
        let mut tasks: JoinSet<()> = JoinSet::new();
        while !stop.load(Ordering::Acquire) {
            while tasks.try_join_next().is_some() {}
            let incoming = tokio::select! {
                incoming = endpoint.accept() => match incoming { Some(incoming) => incoming, None => break },
                _ = tokio::time::sleep(Duration::from_millis(20)) => continue,
            };
            let Some(slot) = Budget::reserve(&connections, MAX_CONNECTIONS_PER_SERVICE) else {
                incoming.refuse();
                continue;
            };
            let service = self.clone();
            tasks.spawn(async move {
                let _slot = slot;
                let Ok(Ok(connection)) = tokio::time::timeout(HANDSHAKE_TIMEOUT, incoming).await
                else {
                    return;
                };
                let _ = service.serve_connection(connection).await;
            });
        }
        endpoint.set_alpns(Vec::new());
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
        Ok(())
    }
}

fn stop_stream(mut send: SendStream, mut recv: RecvStream, code: u32) {
    let _ = recv.stop(VarInt::from_u32(code));
    let _ = send.reset(VarInt::from_u32(code));
}

/// Read exactly one bounded request frame. The declared length is checked
/// against [`MAX_FRAME_BYTES`] before any payload byte is requested.
async fn read_request(recv: &mut RecvStream) -> Result<Vec<u8>, HabitatLinkError> {
    fn read_failure(error: ReadExactError) -> HabitatLinkError {
        match error {
            ReadExactError::FinishedEarly(_) => HabitatLinkError::Truncated,
            ReadExactError::ReadError(_) => HabitatLinkError::Connection,
        }
    }
    let mut prefix = [0u8; 4];
    recv.read_exact(&mut prefix).await.map_err(read_failure)?;
    let len = u32::from_be_bytes(prefix) as usize;
    if len == 0 {
        return Err(HabitatLinkError::Empty);
    }
    if len > MAX_FRAME_BYTES {
        return Err(HabitatLinkError::Oversize);
    }
    let mut frame = vec![0u8; 4 + len];
    frame[..4].copy_from_slice(&prefix);
    recv.read_exact(&mut frame[4..])
        .await
        .map_err(read_failure)?;
    let mut extra = [0u8; 1];
    match recv.read(&mut extra).await {
        Ok(None) => {}
        Ok(Some(_)) => return Err(HabitatLinkError::TrailingBytes),
        Err(_) => return Err(HabitatLinkError::Connection),
    }
    decode_frame(&frame)
}

async fn serve_stream(
    handler: Arc<dyn HabitatLinkHandler>,
    mut send: SendStream,
    mut recv: RecvStream,
) -> Result<(), HabitatLinkError> {
    let envelope = match tokio::time::timeout(FRAME_READ_TIMEOUT, read_request(&mut recv)).await {
        Ok(Ok(envelope)) => envelope,
        Ok(Err(error)) => {
            stop_stream(send, recv, STOP_FRAME_REJECTED);
            return Err(error);
        }
        Err(_) => {
            stop_stream(send, recv, STOP_TIMEOUT);
            return Err(HabitatLinkError::Timeout);
        }
    };
    // The habitat handler may block; it runs on a bounded blocking worker.
    let processed = tokio::task::spawn_blocking(move || handler.handle(&envelope)).await;
    let reply = match processed {
        Ok(Ok(reply)) => reply,
        Ok(Err(error)) => {
            let _ = send.reset(VarInt::from_u32(RESET_HANDLER));
            return Err(error);
        }
        Err(_) => {
            let _ = send.reset(VarInt::from_u32(RESET_HANDLER));
            return Err(HabitatLinkError::Handler);
        }
    };
    let frame = match encode_frame(&reply) {
        Ok(frame) => frame,
        Err(error) => {
            let _ = send.reset(VarInt::from_u32(RESET_HANDLER));
            return Err(error);
        }
    };
    tokio::time::timeout(REPLY_WRITE_TIMEOUT, async {
        send.write_all(&frame)
            .await
            .map_err(|_| HabitatLinkError::Connection)?;
        send.finish().map_err(|_| HabitatLinkError::Connection)?;
        send.stopped()
            .await
            .map_err(|_| HabitatLinkError::Connection)?;
        Ok(())
    })
    .await
    .map_err(|_| HabitatLinkError::Timeout)?
}

/// Send one envelope to a Habitat Link peer and return its reply envelope,
/// within [`CLIENT_EXCHANGE_TIMEOUT`].
pub async fn send_envelope(
    endpoint: &Endpoint,
    addr: EndpointAddr,
    envelope: &[u8],
) -> Result<Vec<u8>, HabitatLinkError> {
    send_envelope_until(
        endpoint,
        addr,
        envelope,
        Instant::now() + CLIENT_EXCHANGE_TIMEOUT,
    )
    .await
}

/// Send one envelope within an absolute deadline. The request is validated
/// before any connection is opened. A timeout after the frame was written
/// leaves the habitat's outcome uncertain; the envelope's operation identity
/// is what makes a retry safe, not this transport.
pub async fn send_envelope_until(
    endpoint: &Endpoint,
    addr: EndpointAddr,
    envelope: &[u8],
    deadline: Instant,
) -> Result<Vec<u8>, HabitatLinkError> {
    let request = encode_frame(envelope)?;
    if Instant::now() >= deadline {
        return Err(HabitatLinkError::Timeout);
    }
    let connection = tokio::time::timeout_at(
        deadline.min(Instant::now() + HANDSHAKE_TIMEOUT).into(),
        endpoint.connect(addr, HABITAT_LINK_ALPN),
    )
    .await
    .map_err(|_| HabitatLinkError::Timeout)?
    .map_err(|_| HabitatLinkError::Connection)?;
    let result = tokio::time::timeout_at(deadline.into(), async {
        let (mut send, mut recv) = connection
            .open_bi()
            .await
            .map_err(|_| HabitatLinkError::Connection)?;
        send.write_all(&request)
            .await
            .map_err(|_| HabitatLinkError::Connection)?;
        send.finish().map_err(|_| HabitatLinkError::Connection)?;
        read_request(&mut recv).await
    })
    .await
    .map_err(|_| HabitatLinkError::Timeout)
    .and_then(|result| result);
    connection.close(VarInt::from_u32(0), b"done");
    result
}
