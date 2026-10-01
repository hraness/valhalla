//! Read-only, explicitly selected public sources over authenticated Iroh QUIC.
//!
//! Network workers only await an actor-owned handler. Cancelling their futures
//! cannot cancel or detach durable actor work. Stop through the shutdown watch
//! and await `serve`: it drains network workers before closing its endpoint.

use iroh::{
    endpoint::{presets, Connection, Incoming, QuicTransportConfig, RecvStream},
    Endpoint, EndpointAddr, RelayMode,
};
use serde::Serialize;
use std::{future::Future, sync::Arc, time::Duration};
use tokio::{
    sync::{watch, Semaphore},
    task::JoinSet,
    time::{timeout, timeout_at, Instant},
};
use vhalla_direct_native::{ReplicaFrame, ReplicaPage};
use vhalla_direct_room::{
    RoomId, SignedGenesis, MAX_EVENT_BYTES, MAX_GENESIS_BYTES, MAX_POLICY_BYTES,
};
use vhalla_direct_sync::{
    Checkpoint, FrameKind, MAX_PAGE_FRAMES, MAX_SNAPSHOT_BYTES, MAX_SNAPSHOT_RECORDS,
};

pub(super) const ALPN: &[u8] = b"valhalla/direct-sync/1";
const MAX_CONNECTIONS: usize = 16;
const MAX_CLIENT_CALLS: usize = 16;
const MAX_REQUEST_BYTES: usize = 4 * 1024;
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
const REQUEST_MAGIC: &[u8; 8] = b"VHDPQ001";
const RESPONSE_MAGIC: &[u8; 8] = b"VHDPS001";

#[derive(Clone, Copy)]
struct Deadlines {
    frame: Duration,
    backend: Duration,
}
impl Default for Deadlines {
    fn default() -> Self {
        Self {
            frame: Duration::from_secs(2),
            backend: Duration::from_secs(30),
        }
    }
}

/// Static errors reveal no peer-supplied text, account data or local paths.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PeerError {
    Bounds,
    Malformed,
    Scope,
    Capacity,
    Timeout,
    Unavailable,
}
impl core::fmt::Display for PeerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for PeerError {}
type Result<T> = std::result::Result<T, PeerError>;

/// No append, join, peer configuration, signing or administration wire verb.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum Request {
    Genesis {
        room: RoomId,
    },
    Head {
        room: RoomId,
    },
    Page {
        room: RoomId,
        checkpoint: Checkpoint,
        after: u64,
        limit: usize,
    },
}
impl Request {
    pub(super) const fn room(&self) -> RoomId {
        match self {
            Self::Genesis { room } | Self::Head { room } | Self::Page { room, .. } => *room,
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum Reply {
    Genesis(Vec<u8>),
    Head(Checkpoint),
    Page(Option<ReplicaPage>),
}

/// Implementations only queue bounded read work to their owning actor and await
/// its result. They retain service custody and never spawn detached durable work.
/// Replies must obey page and frame bounds before allocating their contents.
pub(super) trait Handler: Clone + Send + Sync + 'static {
    fn handle(
        &self,
        authenticated_peer: [u8; 32],
        request: Request,
    ) -> impl Future<Output = Result<Reply>> + Send;
}

/// The identity comes from the authenticated connection, never from wire JSON
/// or a checkpoint's source field. Partial pages still require `Receiver` proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct AuthenticatedReply {
    pub source: [u8; 32],
    pub reply: Reply,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum SelectedPath {
    Direct,
    Relay,
    Unknown,
}

/// A local snapshot of currently open paths, without addresses or path IDs.
/// The selected path is a point-in-time observation, not byte accounting.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub(super) struct PathSnapshot {
    pub(super) selected: SelectedPath,
    pub(super) nonempty: bool,
    pub(super) all_relay: bool,
}
impl PathSnapshot {
    fn capture(connection: &Connection) -> Self {
        let paths = connection.paths();
        Self::from_flags(
            paths
                .iter()
                .map(|path| (path.is_selected(), path.is_ip(), path.is_relay())),
        )
    }

    fn from_flags(paths: impl Iterator<Item = (bool, bool, bool)>) -> Self {
        let mut selected = SelectedPath::Unknown;
        let mut selected_count = 0usize;
        let mut nonempty = false;
        let mut all_relay = true;
        for (is_selected, is_ip, is_relay) in paths {
            nonempty = true;
            all_relay &= is_relay && !is_ip;
            if is_selected {
                selected_count += 1;
                selected = match (is_ip, is_relay) {
                    (true, false) => SelectedPath::Direct,
                    (false, true) => SelectedPath::Relay,
                    _ => SelectedPath::Unknown,
                };
            }
        }
        Self {
            selected: if selected_count == 1 {
                selected
            } else {
                SelectedPath::Unknown
            },
            nonempty,
            all_relay: nonempty && all_relay,
        }
    }
}

/// Captured before sending a request and after checking its authenticated reply.
/// No observer task, path-change wait, retry or extra connection hold is added.
/// Even matching snapshots do not assert which path carried every reply byte.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub(super) struct PathObservation {
    pub(super) before: PathSnapshot,
    pub(super) after: PathSnapshot,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ObservedReply {
    pub(super) response: AuthenticatedReply,
    pub(super) observation: PathObservation,
}

/// Minimal transport with bounded streams and no default relay or discovery.
/// Production callers explicitly select routing and supply their retained key.
pub(super) fn endpoint_builder() -> iroh::endpoint::Builder {
    let transport = QuicTransportConfig::builder()
        .max_concurrent_bidi_streams(1u32.into())
        .max_concurrent_uni_streams(0u32.into())
        .stream_receive_window((256u32 * 1024).into())
        .receive_window((1024u32 * 1024).into())
        .send_window(1024 * 1024)
        .datagram_receive_buffer_size(None)
        .datagram_send_buffer_size(0)
        .build();
    Endpoint::builder(presets::Minimal)
        .relay_mode(RelayMode::Disabled)
        .transport_config(transport)
}

/// One service-wide outbound admission pool; clones share the same 16 permits.
/// This is independent of server connection capacity. Endpoints remain owned
/// by the caller; cancelling a call closes only its connection.
#[derive(Clone)]
pub(super) struct Client {
    permits: Arc<Semaphore>,
    deadlines: Deadlines,
}
impl Default for Client {
    fn default() -> Self {
        Self {
            permits: Arc::new(Semaphore::new(MAX_CLIENT_CALLS)),
            deadlines: Deadlines::default(),
        }
    }
}
impl Client {
    /// Test convenience for callers that do not inspect local observations.
    #[cfg(test)]
    pub(super) async fn call(
        &self,
        endpoint: &Endpoint,
        configured: EndpointAddr,
        request: Request,
    ) -> Result<AuthenticatedReply> {
        self.call_observed(endpoint, configured, request)
            .await
            .map(|result| result.response)
    }

    pub(super) async fn call_observed(
        &self,
        endpoint: &Endpoint,
        configured: EndpointAddr,
        request: Request,
    ) -> Result<ObservedReply> {
        let _permit = self
            .permits
            .try_acquire()
            .map_err(|_| PeerError::Capacity)?;
        let expected = *configured.id.as_bytes();
        check_request(&request, expected)?;
        let raw = encode_request(&request)?;
        let connection = timeout(self.deadlines.frame, endpoint.connect(configured, ALPN))
            .await
            .map_err(|_| PeerError::Timeout)?
            .map_err(|_| PeerError::Unavailable)?;
        let connection = CloseConnection(connection);
        let source = *connection.0.remote_id().as_bytes();
        if source != expected || connection.0.alpn() != ALPN {
            return Err(PeerError::Scope);
        }
        let before = PathSnapshot::capture(&connection.0);
        let mut recv = timeout(self.deadlines.frame, async {
            let (mut send, recv) = connection
                .0
                .open_bi()
                .await
                .map_err(|_| PeerError::Unavailable)?;
            send.write_all(&raw)
                .await
                .map_err(|_| PeerError::Unavailable)?;
            send.finish().map_err(|_| PeerError::Unavailable)?;
            Ok(recv)
        })
        .await
        .map_err(|_| PeerError::Timeout)??;
        let raw = read_reply(&mut recv, self.deadlines).await?;
        let reply = decode_reply(&raw)?;
        check_reply(&request, &reply, source)?;
        let after = PathSnapshot::capture(&connection.0);
        Ok(ObservedReply {
            response: AuthenticatedReply { source, reply },
            observation: PathObservation { before, after },
        })
    }
}

struct CloseConnection(Connection);
impl Drop for CloseConnection {
    fn drop(&mut self) {
        self.0.close(0u32.into(), b"done");
    }
}

/// Own the endpoint and every inbound network task through shutdown. The caller
/// signals the watch and awaits this function; it must not detach this future.
pub(super) async fn serve<H: Handler>(
    endpoint: Endpoint,
    handler: H,
    shutdown: watch::Receiver<bool>,
) -> Result<()> {
    serve_with(endpoint, handler, shutdown, Deadlines::default()).await
}
async fn serve_with<H: Handler>(
    endpoint: Endpoint,
    handler: H,
    mut shutdown: watch::Receiver<bool>,
    deadlines: Deadlines,
) -> Result<()> {
    endpoint.set_alpns(vec![ALPN.to_vec()]);
    let source = *endpoint.id().as_bytes();
    let mut tasks = JoinSet::new();
    let mut failed = false;
    loop {
        if *shutdown.borrow() {
            break;
        }
        tokio::select! {
            biased;
            changed = shutdown.changed() => { if changed.is_err() || *shutdown.borrow() { break; } }
            done = tasks.join_next(), if !tasks.is_empty() => {
                if done.is_some_and(|result| result.is_err()) { failed = true; break; }
            }
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else { break; };
                if tasks.len() >= MAX_CONNECTIONS { incoming.refuse(); continue; }
                let handler = handler.clone();
                tasks.spawn(async move { serve_one(incoming, handler, source, deadlines).await });
            }
        }
    }
    endpoint.set_alpns(Vec::new());
    tasks.abort_all();
    while let Some(outcome) = tasks.join_next().await {
        if outcome.is_err_and(|error| error.is_panic()) {
            failed = true;
        }
    }
    endpoint.close().await;
    drop(endpoint);
    drop(handler);
    if failed {
        Err(PeerError::Unavailable)
    } else {
        Ok(())
    }
}

// On cancellation the connection closes before the worker's custody clone is
// released. The base handler remains held by `serve` until all workers drain.
struct Worker<H> {
    connection: CloseConnection,
    handler: H,
}
async fn serve_one<H: Handler>(
    incoming: Incoming,
    handler: H,
    source: [u8; 32],
    deadlines: Deadlines,
) -> Result<()> {
    let connection = timeout(deadlines.frame, incoming)
        .await
        .map_err(|_| PeerError::Timeout)?
        .map_err(|_| PeerError::Unavailable)?;
    let worker = Worker {
        connection: CloseConnection(connection),
        handler,
    };
    if worker.connection.0.alpn() != ALPN {
        return Err(PeerError::Scope);
    }
    let peer = *worker.connection.0.remote_id().as_bytes();
    let (mut send, request) = timeout(deadlines.frame, async {
        let (send, mut recv) = worker
            .connection
            .0
            .accept_bi()
            .await
            .map_err(|_| PeerError::Unavailable)?;
        let raw = recv
            .read_to_end(MAX_REQUEST_BYTES)
            .await
            .map_err(|_| PeerError::Malformed)?;
        let request = decode_request(&raw)?;
        check_request(&request, source)?;
        Ok((send, request))
    })
    .await
    .map_err(|_| PeerError::Timeout)??;
    let result = timeout(
        deadlines.backend,
        worker.handler.handle(peer, request.clone()),
    )
    .await
    .map_err(|_| PeerError::Timeout)
    .and_then(|result| result)
    .and_then(|reply| {
        check_reply(&request, &reply, source)?;
        Ok(reply)
    });
    let raw = encode_reply(result)?;
    timeout(deadlines.frame, async {
        send.write_all(&raw)
            .await
            .map_err(|_| PeerError::Unavailable)?;
        send.finish().map_err(|_| PeerError::Unavailable)?;
        send.stopped().await.map_err(|_| PeerError::Unavailable)?;
        Ok(())
    })
    .await
    .map_err(|_| PeerError::Timeout)?
}

async fn read_reply(recv: &mut RecvStream, deadlines: Deadlines) -> Result<Vec<u8>> {
    let deadline = Instant::now() + deadlines.backend + deadlines.frame;
    let mut first = [0; 1];
    timeout_at(deadline, recv.read_exact(&mut first))
        .await
        .map_err(|_| PeerError::Timeout)?
        .map_err(|_| PeerError::Malformed)?;
    // First byte ends backend waiting. The complete remaining frame has one
    // absolute budget; an attacker cannot extend it by trickling bytes.
    let remainder = timeout_at(
        deadline.min(Instant::now() + deadlines.frame),
        recv.read_to_end(MAX_RESPONSE_BYTES - 1),
    )
    .await
    .map_err(|_| PeerError::Timeout)?
    .map_err(|_| PeerError::Malformed)?;
    let mut raw = Vec::with_capacity(1 + remainder.len());
    raw.push(first[0]);
    raw.extend(remainder);
    Ok(raw)
}

fn check_checkpoint(checkpoint: Checkpoint, room: RoomId, source: [u8; 32]) -> Result<()> {
    if room == RoomId::ZERO
        || checkpoint.room != room
        || checkpoint.source != source
        || source == [0; 32]
        || checkpoint.epoch == [0; 32]
    {
        return Err(PeerError::Scope);
    }
    if checkpoint.records == 0
        || checkpoint.records > MAX_SNAPSHOT_RECORDS
        || checkpoint.bytes < checkpoint.records
        || checkpoint.bytes > MAX_SNAPSHOT_BYTES
    {
        return Err(PeerError::Bounds);
    }
    Ok(())
}
fn check_request(request: &Request, source: [u8; 32]) -> Result<()> {
    if request.room() == RoomId::ZERO {
        return Err(PeerError::Scope);
    }
    if let Request::Page {
        room,
        checkpoint,
        after,
        limit,
    } = request
    {
        check_checkpoint(*checkpoint, *room, source)?;
        if *limit == 0 || *limit > MAX_PAGE_FRAMES || *after > checkpoint.records {
            return Err(PeerError::Bounds);
        }
    }
    Ok(())
}
fn check_frame(frame: &ReplicaFrame) -> Result<()> {
    let max = match frame.kind {
        FrameKind::Genesis => MAX_GENESIS_BYTES,
        FrameKind::Policy => MAX_POLICY_BYTES,
        FrameKind::Event => MAX_EVENT_BYTES,
    };
    if frame.bytes.is_empty() || frame.bytes.len() > max {
        return Err(PeerError::Bounds);
    }
    Ok(())
}
fn check_reply(request: &Request, reply: &Reply, source: [u8; 32]) -> Result<()> {
    match (request, reply) {
        (Request::Genesis { room }, Reply::Genesis(raw)) => {
            if raw.is_empty() || raw.len() > MAX_GENESIS_BYTES {
                return Err(PeerError::Bounds);
            }
            SignedGenesis::decode(raw)
                .and_then(|signed| signed.verify_pin(*room))
                .map_err(|_| PeerError::Scope)?;
        }
        (Request::Head { room }, Reply::Head(checkpoint)) => {
            check_checkpoint(*checkpoint, *room, source)?
        }
        (
            Request::Page {
                checkpoint, after, ..
            },
            Reply::Page(None),
        ) if *after == checkpoint.records => {}
        (
            Request::Page {
                room,
                checkpoint,
                after,
                limit,
            },
            Reply::Page(Some(page)),
        ) => {
            check_checkpoint(page.checkpoint, *room, source)?;
            if page.checkpoint != *checkpoint {
                return Err(PeerError::Scope);
            }
            let count = (checkpoint.records - after).min(*limit as u64) as usize;
            if count == 0
                || page.frames.len() != count
                || page.frames.len() > MAX_PAGE_FRAMES
                || page.first != after + 1
                || page.last != after + count as u64
            {
                return Err(PeerError::Malformed);
            }
            for (offset, frame) in page.frames.iter().enumerate() {
                check_frame(frame)?;
                if (page.first + offset as u64 == 1) != (frame.kind == FrameKind::Genesis) {
                    return Err(PeerError::Malformed);
                }
            }
        }
        _ => return Err(PeerError::Malformed),
    }
    Ok(())
}

fn put_checkpoint(raw: &mut Vec<u8>, checkpoint: Checkpoint) {
    raw.extend(checkpoint.source);
    raw.extend(checkpoint.room.as_bytes());
    raw.extend(checkpoint.epoch);
    raw.extend(checkpoint.records.to_be_bytes());
    raw.extend(checkpoint.bytes.to_be_bytes());
    raw.extend(checkpoint.digest);
}
fn encode_request(request: &Request) -> Result<Vec<u8>> {
    let mut raw = REQUEST_MAGIC.to_vec();
    raw.push(match request {
        Request::Genesis { .. } => 1,
        Request::Head { .. } => 2,
        Request::Page { .. } => 3,
    });
    raw.extend(request.room().as_bytes());
    if let Request::Page {
        checkpoint,
        after,
        limit,
        ..
    } = request
    {
        if *limit == 0 || *limit > MAX_PAGE_FRAMES {
            return Err(PeerError::Bounds);
        }
        put_checkpoint(&mut raw, *checkpoint);
        raw.extend(after.to_be_bytes());
        raw.push(*limit as u8);
    }
    Ok(raw)
}
fn decode_request(raw: &[u8]) -> Result<Request> {
    if raw.len() > MAX_REQUEST_BYTES {
        return Err(PeerError::Bounds);
    }
    let mut reader = Reader(raw);
    if reader.take(8)? != REQUEST_MAGIC {
        return Err(PeerError::Malformed);
    }
    let op = reader.byte()?;
    let room = RoomId::from_bytes(reader.array()?);
    let request = match op {
        1 => Request::Genesis { room },
        2 => Request::Head { room },
        3 => Request::Page {
            room,
            checkpoint: reader.checkpoint()?,
            after: reader.integer()?,
            limit: reader.byte()? as usize,
        },
        _ => return Err(PeerError::Malformed),
    };
    reader.finish()?;
    Ok(request)
}
fn encode_reply(result: Result<Reply>) -> Result<Vec<u8>> {
    let mut raw = RESPONSE_MAGIC.to_vec();
    match result {
        Err(error) => {
            raw.extend([255, error_code(error)]);
        }
        Ok(Reply::Genesis(bytes)) => {
            if bytes.is_empty() || bytes.len() > MAX_GENESIS_BYTES {
                return Err(PeerError::Bounds);
            }
            raw.push(1);
            put_bytes(&mut raw, &bytes);
        }
        Ok(Reply::Head(checkpoint)) => {
            raw.push(2);
            put_checkpoint(&mut raw, checkpoint);
        }
        Ok(Reply::Page(page)) => {
            raw.push(3);
            if let Some(page) = page {
                if page.frames.is_empty() || page.frames.len() > MAX_PAGE_FRAMES {
                    return Err(PeerError::Bounds);
                }
                // Validate every allocation bound before copying a reply payload.
                for frame in &page.frames {
                    check_frame(frame)?;
                }
                raw.push(1);
                put_checkpoint(&mut raw, page.checkpoint);
                raw.extend(page.first.to_be_bytes());
                raw.extend(page.last.to_be_bytes());
                raw.push(page.frames.len() as u8);
                for frame in page.frames {
                    raw.push(frame.kind as u8);
                    put_bytes(&mut raw, &frame.bytes);
                }
            } else {
                raw.push(0);
            }
        }
    }
    if raw.len() > MAX_RESPONSE_BYTES {
        return Err(PeerError::Bounds);
    }
    Ok(raw)
}
fn put_bytes(raw: &mut Vec<u8>, bytes: &[u8]) {
    raw.extend((bytes.len() as u32).to_be_bytes());
    raw.extend(bytes);
}
fn decode_reply(raw: &[u8]) -> Result<Reply> {
    if raw.len() > MAX_RESPONSE_BYTES {
        return Err(PeerError::Bounds);
    }
    let mut reader = Reader(raw);
    if reader.take(8)? != RESPONSE_MAGIC {
        return Err(PeerError::Malformed);
    }
    let reply = match reader.byte()? {
        1 => Reply::Genesis(reader.bytes(MAX_GENESIS_BYTES)?.to_vec()),
        2 => Reply::Head(reader.checkpoint()?),
        3 => Reply::Page(match reader.byte()? {
            0 => None,
            1 => {
                let checkpoint = reader.checkpoint()?;
                let first = reader.integer()?;
                let last = reader.integer()?;
                let count = reader.byte()? as usize;
                if count == 0 || count > MAX_PAGE_FRAMES {
                    return Err(PeerError::Bounds);
                }
                let mut frames = Vec::with_capacity(count);
                for _ in 0..count {
                    let (kind, bound) = match reader.byte()? {
                        1 => (FrameKind::Genesis, MAX_GENESIS_BYTES),
                        2 => (FrameKind::Policy, MAX_POLICY_BYTES),
                        3 => (FrameKind::Event, MAX_EVENT_BYTES),
                        _ => return Err(PeerError::Malformed),
                    };
                    frames.push(ReplicaFrame {
                        kind,
                        bytes: reader.bytes(bound)?.to_vec(),
                    });
                }
                Some(ReplicaPage {
                    checkpoint,
                    first,
                    last,
                    frames,
                })
            }
            _ => return Err(PeerError::Malformed),
        }),
        255 => {
            let error = decode_error(reader.byte()?)?;
            reader.finish()?;
            return Err(error);
        }
        _ => return Err(PeerError::Malformed),
    };
    reader.finish()?;
    Ok(reply)
}
fn error_code(error: PeerError) -> u8 {
    match error {
        PeerError::Bounds => 1,
        PeerError::Malformed => 2,
        PeerError::Scope => 3,
        PeerError::Capacity => 4,
        PeerError::Timeout => 5,
        PeerError::Unavailable => 6,
    }
}
fn decode_error(code: u8) -> Result<PeerError> {
    Ok(match code {
        1 => PeerError::Bounds,
        2 => PeerError::Malformed,
        3 => PeerError::Scope,
        4 => PeerError::Capacity,
        5 => PeerError::Timeout,
        6 => PeerError::Unavailable,
        _ => return Err(PeerError::Malformed),
    })
}
struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let result = self.0.get(..n).ok_or(PeerError::Malformed)?;
        self.0 = &self.0[n..];
        Ok(result)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.take(N)?.try_into().map_err(|_| PeerError::Malformed)
    }
    fn byte(&mut self) -> Result<u8> {
        Ok(self.array::<1>()?[0])
    }
    fn integer(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    fn bytes(&mut self, max: usize) -> Result<&'a [u8]> {
        let n = u32::from_be_bytes(self.array()?) as usize;
        if n == 0 || n > max {
            return Err(PeerError::Bounds);
        }
        self.take(n)
    }
    fn checkpoint(&mut self) -> Result<Checkpoint> {
        Ok(Checkpoint {
            source: self.array()?,
            room: RoomId::from_bytes(self.array()?),
            epoch: self.array()?,
            records: self.integer()?,
            bytes: self.integer()?,
            digest: self.array()?,
        })
    }
    fn finish(self) -> Result<()> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(PeerError::Malformed)
        }
    }
}

#[cfg(test)]
#[path = "peer_tests.rs"]
mod tests;
