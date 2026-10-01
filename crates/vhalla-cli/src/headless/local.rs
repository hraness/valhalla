//! Bounded local transport using the Hraness control-kit wire format.
//!
//! One actor owns the backend. Shutdown stops intake while preserving accepted
//! durable work; network timeouts never cancel it or create a fresh operation.

mod custody;

use custody::Guard;
use hraness_control_kit::{control, ErrorBody, ErrorCode};
use serde::Serialize;
use serde_json::{json, Value};
use std::{
    future::{poll_fn, Future},
    io,
    io::Write,
    path::Path,
    pin::Pin,
    sync::Arc,
    task::Poll,
    time::Duration,
};
use tokio::{
    io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader},
    net::{UnixListener, UnixStream},
    sync::{mpsc, oneshot, watch, RwLock, Semaphore},
    task::JoinSet,
    time::timeout,
};

pub(super) const AGENT_PROTOCOL: &str = "valhalla.rooms/1";
const MAX_REQUEST_BYTES: usize = 64 * 1024;
// Trusted administration also carries bounded private invitations/control
// artifacts (up to 192 KiB before JSON encoding). Agent tools retain 64 KiB.
const MAX_ADMIN_REQUEST_BYTES: usize = 512 * 1024;
const MAX_RESPONSE_BYTES: usize = control::DEFAULT_MAX_BYTES;
const MAX_CLIENTS: usize = 16;
const RESERVED_ADMIN_CLIENTS: usize = 4;
const MAX_QUEUED: usize = 32;

#[derive(Clone, Copy)]
struct Deadlines {
    frame: Duration,
    response: Duration,
}

impl Default for Deadlines {
    fn default() -> Self {
        Self {
            frame: Duration::from_secs(2),
            response: Duration::from_secs(30),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Channel {
    Admin,
    Agent,
}

impl Channel {
    const fn request_limit(self) -> usize {
        match self {
            Self::Admin => MAX_ADMIN_REQUEST_BYTES,
            Self::Agent => MAX_REQUEST_BYTES,
        }
    }
}

/// Implementations own their room/account handles and all durable work. They
/// must not detach mutations into tasks that outlive the backend value.
pub(super) trait Backend {
    fn dispatch(
        &mut self,
        channel: Channel,
        request: Value,
    ) -> impl Future<Output = Result<Reply, ErrorBody>>;

    /// End every retained output authorization after transport custody fails or
    /// before shutdown. This must not discard or cancel durable room work.
    fn invalidate(&mut self) {}

    /// One finite maintenance step. Room failures are isolated by the backend;
    /// an error here means global service custody is no longer usable.
    fn tick(&mut self) -> impl Future<Output = Result<(), ErrorBody>> {
        async { Ok(()) }
    }

    /// Public, read-only peer requests run on this same owner through an
    /// independently bounded queue. Implementations must never expose local
    /// reservations, room keys, private content or administration here.
    fn peer(
        &mut self,
        _authenticated_peer: [u8; 32],
        _request: super::peer::Request,
    ) -> impl Future<Output = Result<super::peer::Reply, super::peer::PeerError>> {
        async { Err(super::peer::PeerError::Unavailable) }
    }
}

/// An owned, synchronous final authority check. It may retain revocation and
/// clock state, but never a room/controller handle or a renewable allowance.
pub(super) struct OutputPermit(Arc<dyn Fn() -> bool + Send + Sync>);
impl OutputPermit {
    pub(super) fn new(check: impl Fn() -> bool + Send + Sync + 'static) -> Self {
        Self(Arc::new(check))
    }
    fn check(&self) -> Result<(), ErrorBody> {
        if (self.0)() {
            Ok(())
        } else {
            Err(ErrorBody::new(
                ErrorCode::PermissionDenied,
                "The grant ended before the response was released.",
            ))
        }
    }
}

/// Authorization travels with a response until the actual transport release.
pub(super) struct Reply {
    value: Value,
    permit: Option<OutputPermit>,
}
impl Reply {
    pub(super) fn unrestricted(value: Value) -> Self {
        Self {
            value,
            permit: None,
        }
    }
    pub(super) fn guarded(value: Value, permit: OutputPermit) -> Self {
        Self {
            value,
            permit: Some(permit),
        }
    }
    pub(super) fn check_release(&self) -> Result<(), ErrorBody> {
        self.permit.as_ref().map_or(Ok(()), OutputPermit::check)
    }
    #[cfg(test)]
    pub(super) fn checked_value(&self) -> Result<&Value, ErrorBody> {
        self.check_release()?;
        Ok(&self.value)
    }
}

struct Call {
    channel: Channel,
    request: Value,
    reply: oneshot::Sender<Result<Reply, ErrorBody>>,
}

fn unavailable() -> ErrorBody {
    ErrorBody::new(
        ErrorCode::OwnerUnavailable,
        "The service is unavailable; retry the same operation.",
    )
}

fn usage(message: &str) -> ErrorBody {
    ErrorBody::new(ErrorCode::Usage, message)
}

struct LimitedWriter {
    bytes: Vec<u8>,
    limit: usize,
}
impl Write for LimitedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
            return Err(io::Error::other("frame limit"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn encode(value: &impl Serialize, limit: usize) -> Result<Vec<u8>, ErrorBody> {
    let mut writer = LimitedWriter {
        bytes: Vec::new(),
        limit: limit - 1,
    };
    serde_json::to_writer(&mut writer, value)
        .map_err(|_| usage("The frame exceeds the supported size."))?;
    writer.bytes.push(b'\n');
    Ok(writer.bytes)
}

fn response(result: Result<Value, ErrorBody>) -> Vec<u8> {
    let envelope = match result {
        Ok(value) => json!({"ok": true, "result": value}),
        Err(error) => json!({"ok": false, "error": error}),
    };
    encode(&envelope, MAX_RESPONSE_BYTES).unwrap_or_else(|_| {
        encode(
            &json!({"ok": false, "error": ErrorBody::new(
                ErrorCode::Internal, "The response exceeds the supported page size."
            )}),
            MAX_RESPONSE_BYTES,
        )
        .expect("fixed error fits")
    })
}

fn prepare_response(result: Result<Reply, ErrorBody>) -> (Vec<u8>, Option<OutputPermit>) {
    match result {
        Err(error) => (response(Err(error)), None),
        Ok(reply) => {
            let Reply { value, permit } = reply;
            (response(Ok(value)), permit)
        }
    }
}

async fn write_authorized_frame(
    writer: &mut (impl AsyncWrite + Unpin),
    mut frame: &[u8],
    guard: &Guard,
    permit: Option<&OutputPermit>,
) -> Result<(), ()> {
    while !frame.is_empty() {
        let written = poll_fn(|cx| {
            // The actor's read hold cannot stop the clock or filesystem changes.
            // Check immediately before every write poll, including resumed
            // Pending writes and successive partial writes in the same poll.
            if guard
                .check()
                .and_then(|()| permit.map_or(Ok(()), OutputPermit::check))
                .is_err()
            {
                return Poll::Ready(Err(()));
            }
            Pin::new(&mut *writer)
                .poll_write(cx, frame)
                .map(|result| result.map_err(|_| ()))
        })
        .await?;
        if written == 0 {
            return Err(());
        }
        frame = &frame[written..];
    }
    Ok(())
}

async fn write_response(
    writer: &mut (impl AsyncWrite + Unpin),
    result: Result<Reply, ErrorBody>,
    frontend: &Frontend,
    stop: &mut watch::Receiver<bool>,
) -> Result<(), ()> {
    // Encode first. A read hold then covers the final authority check and the
    // entire bounded write. The actor cannot change room authority between its
    // native operation and grant audit while this response is being released.
    let (frame, mut permit) = prepare_response(result);
    timeout(frontend.deadlines.frame, async {
        let _output = if permit.is_some() {
            Some(tokio::select! {
                biased;
                () = stopped(stop) => return Err(()),
                output = frontend.output.read() => output,
            })
        } else {
            None
        };
        let frame = match frontend
            .guard
            .check()
            .and_then(|()| permit.as_ref().map_or(Ok(()), OutputPermit::check))
        {
            Ok(()) => frame,
            Err(error) => {
                // No payload bytes have been written. A refusal may replace the
                // complete frame, but the error itself carries no grant data.
                permit = None;
                response(Err(error))
            }
        };
        // A later refusal terminates the connection, even before first progress.
        // Never append an error envelope to a partially released frame.
        write_authorized_frame(writer, &frame, &frontend.guard, permit.as_ref()).await
    })
    .await
    .map_err(|_| ())?
}

async fn read_frame(
    reader: &mut (impl AsyncBufRead + Unpin),
    limit: usize,
) -> Result<Option<Vec<u8>>, ErrorBody> {
    let mut line = Vec::new();
    loop {
        let bytes = reader.fill_buf().await.map_err(|_| unavailable())?;
        if bytes.is_empty() {
            return if line.is_empty() {
                Ok(None)
            } else {
                Err(usage("The frame is unterminated."))
            };
        }
        let end = bytes
            .iter()
            .position(|byte| *byte == b'\n')
            .map(|index| index + 1);
        let count = end.unwrap_or(bytes.len());
        if count > limit.saturating_sub(line.len()) {
            return Err(usage("The frame exceeds the supported size."));
        }
        line.extend_from_slice(&bytes[..count]);
        reader.consume(count);
        if end.is_some() {
            return Ok(Some(line));
        }
    }
}

enum Parsed {
    Hello,
    Stop,
    Dispatch(Value),
}

fn parse(line: &[u8], channel: Channel, guard: &Guard) -> Result<Parsed, ErrorBody> {
    guard.check()?;
    let value: Value = serde_json::from_slice(line).map_err(|_| usage("The frame is not JSON."))?;
    let frame = value
        .as_object()
        .ok_or_else(|| usage("The frame is not an object."))?;
    if frame.get("v").and_then(Value::as_u64) != Some(control::WIRE_VERSION) {
        return Err(usage("Unsupported wire version."));
    }
    let request = frame
        .get("request")
        .ok_or_else(|| usage("The frame has no request."))?;
    let op = request.get("op").and_then(Value::as_str);
    match channel {
        Channel::Admin => {
            if !frame
                .get("cap")
                .and_then(Value::as_str)
                .is_some_and(|cap| guard.accepts_cap(cap))
            {
                return Err(ErrorBody::new(
                    ErrorCode::PermissionDenied,
                    "Invalid admin capability.",
                ));
            }
            match op {
                Some("control.hello") => Ok(Parsed::Hello),
                Some("control.stop") => Ok(Parsed::Stop),
                _ => Ok(Parsed::Dispatch(request.clone())),
            }
        }
        Channel::Agent => {
            if frame.contains_key("cap") {
                return Err(ErrorBody::new(
                    ErrorCode::PermissionDenied,
                    "Admin requests require the admin socket.",
                ));
            }
            match frame.get("protocol").and_then(Value::as_str) {
                Some(control::CONTROL_PROTOCOL) if op == Some("control.hello") => Ok(Parsed::Hello),
                Some(AGENT_PROTOCOL) if !op.is_some_and(|op| op.starts_with("control.")) => {
                    Ok(Parsed::Dispatch(request.clone()))
                }
                _ => Err(ErrorBody::new(
                    ErrorCode::PermissionDenied,
                    "Unknown or unauthorized agent protocol.",
                )),
            }
        }
    }
}

async fn stopped(stop: &mut watch::Receiver<bool>) {
    while !*stop.borrow_and_update() {
        if stop.changed().await.is_err() {
            break;
        }
    }
}

struct Frontend {
    queue: mpsc::Sender<Call>,
    stop: watch::Sender<bool>,
    admin_clients: Arc<Semaphore>,
    agent_clients: Arc<Semaphore>,
    guard: Arc<Guard>,
    deadlines: Deadlines,
    output: Arc<RwLock<()>>,
}

async fn connection(stream: UnixStream, channel: Channel, frontend: Arc<Frontend>) {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut stop = frontend.stop.subscribe();
    loop {
        let line = tokio::select! {
            biased;
            () = stopped(&mut stop) => break,
            result = timeout(frontend.deadlines.frame, read_frame(&mut reader, channel.request_limit())) => {
                match result {
                    Ok(Ok(Some(line))) => line,
                    Ok(Ok(None)) | Err(_) => break,
                    Ok(Err(error)) => {
                        let _ = timeout(frontend.deadlines.frame, writer.write_all(&response(Err(error)))).await;
                        break;
                    }
                }
            }
        };
        let result = match parse(&line, channel, &frontend.guard) {
            Ok(Parsed::Hello) => Ok(Reply::unrestricted(
                serde_json::to_value(frontend.guard.info()).expect("owner serializes"),
            )),
            Ok(Parsed::Stop) => {
                frontend.stop.send_replace(true);
                Ok(Reply::unrestricted(json!({"stopping": true})))
            }
            Ok(Parsed::Dispatch(request)) => {
                let (reply, answer) = oneshot::channel();
                if frontend
                    .queue
                    .try_send(Call {
                        channel,
                        request,
                        reply,
                    })
                    .is_err()
                {
                    Err(unavailable())
                } else {
                    tokio::select! {
                        result = timeout(frontend.deadlines.response, answer) => result
                            .map_err(|_| unavailable()).and_then(|answer| answer.map_err(|_| unavailable()))
                            .and_then(|result| result),
                        () = stopped(&mut stop) => Err(unavailable()),
                    }
                }
            }
            Err(error) => Err(error),
        };
        if write_response(&mut writer, result, &frontend, &mut stop)
            .await
            .is_err()
        {
            break;
        }
    }
}

async fn listener(listener: UnixListener, channel: Channel, frontend: Arc<Frontend>) {
    let mut connections = JoinSet::new();
    let mut stop = frontend.stop.subscribe();
    loop {
        tokio::select! {
            biased;
            () = stopped(&mut stop) => break,
            _ = connections.join_next(), if !connections.is_empty() => {},
            accepted = listener.accept() => {
                let Ok((stream, _)) = accepted else {
                    frontend.stop.send_replace(true);
                    break;
                };
                let clients = match channel {
                    Channel::Admin => &frontend.admin_clients,
                    Channel::Agent => &frontend.agent_clients,
                };
                if let Ok(permit) = Arc::clone(clients).try_acquire_owned() {
                    let frontend = Arc::clone(&frontend);
                    connections.spawn(async move {
                        let _permit = permit;
                        connection(stream, channel, frontend).await;
                    });
                }
            }
        }
    }
    drop(listener);
    while connections.join_next().await.is_some() {}
}

mod runtime;
#[cfg(test)]
use runtime::serve_with_deadlines;
pub(super) use runtime::{serve_factory, Launch};

#[cfg(test)]
async fn serve(
    home: &Path,
    backend: impl Backend,
    shutdown: impl Future<Output = ()>,
) -> Result<(), ErrorBody> {
    serve_with_deadlines(home, backend, shutdown, Deadlines::default()).await
}

async fn exchange(socket: &Path, channel: Channel, frame: Value) -> Result<Value, ErrorBody> {
    // Bound the complete outgoing envelope before connecting or writing.
    let line = encode(&frame, channel.request_limit())?;
    timeout(Deadlines::default().response, async {
        let mut stream = UnixStream::connect(socket)
            .await
            .map_err(|_| unavailable())?;
        stream.write_all(&line).await.map_err(|_| unavailable())?;
        let mut reader = BufReader::new(stream);
        let reply = read_frame(&mut reader, MAX_RESPONSE_BYTES)
            .await?
            .ok_or_else(unavailable)?;
        let value: Value = serde_json::from_slice(&reply).map_err(|_| unavailable())?;
        match value.get("ok").and_then(Value::as_bool) {
            Some(true) if value.get("error").is_none() => {
                value.get("result").cloned().ok_or_else(unavailable)
            }
            Some(false) if value.get("result").is_none() => Err(serde_json::from_value(
                value.get("error").cloned().ok_or_else(unavailable)?,
            )
            .map_err(|_| unavailable())?),
            _ => Err(unavailable()),
        }
    })
    .await
    .map_err(|_| unavailable())?
}

pub(super) async fn admin_request(home: &Path, request: Value) -> Result<Value, ErrorBody> {
    let paths = custody::preflight(home)?;
    let owner = vhalla_custody::Owner::current().map_err(|_| unavailable())?;
    let cap =
        vhalla_custody::read_private_file(&paths.cap, owner, 64).map_err(|_| unavailable())?;
    let cap = std::str::from_utf8(&cap).map_err(|_| unavailable())?;
    exchange(
        &paths.admin_sock,
        Channel::Admin,
        json!({"v": control::WIRE_VERSION, "cap": cap, "request": request}),
    )
    .await
}

pub(super) async fn agent_request(home: &Path, request: Value) -> Result<Value, ErrorBody> {
    let paths = custody::preflight(home)?;
    exchange(
        &paths.agent_sock,
        Channel::Agent,
        json!({"v": control::WIRE_VERSION, "protocol": AGENT_PROTOCOL, "request": request}),
    )
    .await
}

#[cfg(test)]
mod tests;
