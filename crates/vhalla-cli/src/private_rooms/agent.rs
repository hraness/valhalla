//! Cooperating-host stdio. No provider call, listener, subprocess or transport tool.

use super::{agent_delivery::Driver, files};
use rustix::{
    event::{poll, PollFd, PollFlags, Timespec},
    fs::{fcntl_getfl, fcntl_setfl, fstat, FileType, OFlags},
    io::{read, write, Errno},
};
use std::{
    collections::VecDeque,
    ffi::OsString,
    os::fd::{AsFd, BorrowedFd},
    path::Path,
    time::{Duration, Instant},
};
use vhalla_identity::Identity;
use vhalla_private_native::client::{
    agent_rpc::{
        is_cancellation, LaunchGrant, RpcSession, IO_DEADLINE, MAX_GRANT_BYTES, MAX_REQUEST_BYTES,
    },
    RoomSession,
};

const REFUSED: &str = "agent launch or transport refused; preserve the grant receipt and original room, reconcile uncertain operations, and obtain a new explicit host grant; never delete a receipt to restart";
const HELP: &str = "vhalla private agent-serve ID STORE --grant PRIVATE_JSON [--delivery PRIVATE_JSON] (cooperating-host MCP over pipes; one-use host grant required)";

pub(super) fn run(raw: &[OsString]) -> Result<(), String> {
    if !matches!(raw.len(), 6 | 8)
        || raw[0] != "private"
        || raw[1] != "agent-serve"
        || raw[4] != "--grant"
        || raw[2].is_empty()
        || raw[3].is_empty()
        || raw[5].is_empty()
        || (raw.len() == 8 && (raw[6] != "--delivery" || raw[7].is_empty()))
    {
        return Err(HELP.into());
    }
    serve_paths(
        Path::new(&raw[2]),
        Path::new(&raw[3]),
        Path::new(&raw[5]),
        (raw.len() == 8).then(|| Path::new(&raw[7])),
    )
}

/// Refuse anything but actual stdio peers: never print plaintext to a terminal
/// or silently reuse the ordinary CLI's success banner / file redirection.
pub(super) fn stdio_is_piped() -> Result<(), String> {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    for fd in [stdin.as_fd(), stdout.as_fd()] {
        if !matches!(
            FileType::from_raw_mode(fstat(fd).map_err(|_| REFUSED)?.st_mode),
            FileType::Fifo | FileType::Socket
        ) {
            return Err(HELP.into());
        }
    }
    Ok(())
}

/// Serve one explicitly prepared grant over the current process's stdio.
pub(super) fn serve_paths(
    identity: &Path,
    store: &Path,
    grant: &Path,
    delivery_profile: Option<&Path>,
) -> Result<(), String> {
    stdio_is_piped()?;
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let input = stdin.as_fd();
    let output = stdout.as_fd();
    let _input_flags = Nonblocking::new(input)?;
    let _output_flags = Nonblocking::new(output)?;
    let bytes = files::read(grant, MAX_GRANT_BYTES, false)?;
    let launch = LaunchGrant::decode(&bytes).map_err(|_| REFUSED)?;
    let context = launch.context();
    let identity = Identity::open(identity).map_err(|_| REFUSED)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .map_err(|_| REFUSED)?;
    let room = runtime
        .block_on(RoomSession::open(identity, store, context))
        .map_err(|_| REFUSED)?;
    // Open the independently selected host profile before consuming a grant.
    // This performs no network effect and refuses absent/foreign state.
    let mut delivery = match delivery_profile {
        Some(profile) => Some(Driver::open(profile, context)?),
        None => None,
    };
    let mut rpc = RpcSession::new(room, launch).map_err(|_| REFUSED)?;
    let result = serve(&runtime, &mut rpc, input, output, &mut delivery);
    rpc.revoke();
    if result.is_err() {
        // Custody is already destroyed. The final frame carries only the closed
        // reason, so a client sees why the stream ends instead of a dead server.
        let frame = rpc
            .take_final_frame()
            .unwrap_or_else(|| rpc.closing_notice());
        write_final(output, &frame);
    }
    result
}

/// Best-effort bounded write of one closing frame after custody is gone. It
/// never renews authority, retries a partial data reply or blocks past a few
/// seconds; a peer that already went away simply loses the notice.
fn write_final(output: BorrowedFd<'_>, frame: &[u8]) {
    let mut bytes = frame.to_vec();
    bytes.push(b'\n');
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut offset = 0;
    while offset < bytes.len() && Instant::now() < deadline {
        match write(output, &bytes[offset..]) {
            Ok(0) => return,
            Ok(n) => offset += n,
            Err(Errno::INTR) => continue,
            Err(Errno::AGAIN) => {
                let mut fds = [PollFd::from_borrowed_fd(output, PollFlags::OUT)];
                let remaining = deadline.saturating_duration_since(Instant::now());
                let Ok(timeout) = Timespec::try_from(remaining) else {
                    return;
                };
                if poll(&mut fds, Some(&timeout)).is_err() {
                    return;
                }
            }
            Err(_) => return,
        }
    }
}

struct Nonblocking<'a> {
    fd: BorrowedFd<'a>,
    flags: OFlags,
}
impl<'a> Nonblocking<'a> {
    fn new(fd: BorrowedFd<'a>) -> Result<Self, String> {
        let flags = fcntl_getfl(fd).map_err(|_| REFUSED)?;
        fcntl_setfl(fd, flags | OFlags::NONBLOCK).map_err(|_| REFUSED)?;
        Ok(Self { fd, flags })
    }
}
impl Drop for Nonblocking<'_> {
    fn drop(&mut self) {
        let _ = fcntl_setfl(self.fd, self.flags);
    }
}

/// Bounded buffered complete frames. A peer may legitimately pipeline a batch
/// of requests; a full queue applies backpressure by leaving input unread in
/// the pipe rather than failing.
const MAX_READY: usize = 64;

#[derive(Default)]
struct Frames {
    pending: Vec<u8>,
    /// Bytes already read but not yet framed because `ready` was full. At most
    /// one read buffer can ever sit here, so bursts apply backpressure in the
    /// pipe instead of failing or dropping framed input.
    spill: VecDeque<u8>,
    ready: VecDeque<Vec<u8>>,
    eof: bool,
    partial_deadline: Option<Instant>,
}
impl Frames {
    fn check_deadline(&self) -> Result<(), String> {
        if self.partial_deadline.is_some_and(|d| Instant::now() >= d) {
            return Err(REFUSED.into());
        }
        Ok(())
    }
    fn drain(&mut self, input: BorrowedFd<'_>) -> Result<(), String> {
        let mut buffer = [0; 4096];
        loop {
            self.check_deadline()?;
            if self.spill.is_empty() {
                if self.ready.len() >= MAX_READY {
                    // Safe backpressure: complete frames wait in `ready`; the
                    // rest of the burst stays in the pipe until answered.
                    return Ok(());
                }
                match read(input, &mut buffer) {
                    Ok(0) => {
                        self.eof = true;
                        return Ok(());
                    }
                    Ok(n) => self.spill.extend(&buffer[..n]),
                    Err(Errno::INTR) => continue,
                    Err(Errno::AGAIN) => return Ok(()),
                    Err(_) => return Err(REFUSED.into()),
                }
                self.check_deadline()?;
            }
            while let Some(byte) = self.spill.pop_front() {
                if byte == b'\n' {
                    // Readiness and a final read do not extend the deadline if
                    // this process was descheduled.
                    self.check_deadline()?;
                    // Blank lines carry no frame; MCP permits ignoring them
                    // instead of failing the transport.
                    if self.pending.is_empty() {
                        continue;
                    }
                    if self.ready.len() >= MAX_READY {
                        self.spill.push_front(b'\n');
                        return Ok(());
                    }
                    self.ready.push_back(std::mem::take(&mut self.pending));
                    self.partial_deadline = None;
                } else {
                    if self.pending.len() >= MAX_REQUEST_BYTES {
                        return Err(REFUSED.into());
                    }
                    if self.pending.is_empty() {
                        self.partial_deadline = Some(Instant::now() + IO_DEADLINE);
                    }
                    self.pending.push(byte);
                }
            }
        }
    }
    /// Remove the first buffered cancellation notification, if any. A cancel
    /// never has a reply of its own and must not end the session; the session
    /// itself decides whether its target is still pending.
    fn take_cancellation(&mut self) -> Option<Vec<u8>> {
        let index = self.ready.iter().position(|raw| is_cancellation(raw))?;
        self.ready.remove(index)
    }
    fn deadline(&self, grant: Instant) -> Instant {
        self.partial_deadline
            .map_or(grant, |deadline| deadline.min(grant))
    }
}

fn serve(
    runtime: &tokio::runtime::Runtime,
    rpc: &mut RpcSession,
    input: BorrowedFd<'_>,
    output: BorrowedFd<'_>,
    delivery: &mut Option<Driver>,
) -> Result<(), String> {
    let mut frames = Frames::default();
    let mut next_tick = Instant::now();
    loop {
        rpc.check_release().map_err(|_| REFUSED)?;
        frames.drain(input)?;
        if frames.eof {
            return Ok(());
        }
        if frames.pending.is_empty() && Instant::now() >= next_tick {
            if let Some(driver) = delivery {
                runtime.block_on(driver.tick(rpc))?;
                frames.drain(input)?;
                if frames.eof {
                    return Ok(());
                }
                rpc.check_release().map_err(|_| REFUSED)?;
            }
            next_tick = Instant::now() + Duration::from_secs(1);
        }
        if let Some(raw) = frames.ready.pop_front() {
            let mut response = runtime.block_on(rpc.handle(&raw)).map_err(|_| REFUSED)?;
            if response.is_none() && rpc.waiting().is_some() {
                response =
                    wait_for_change(runtime, rpc, &mut frames, input, delivery, &mut next_tick)?;
            }
            let deadline = (Instant::now() + IO_DEADLINE).min(rpc.deadline());
            // Native custody I/O may complete inside one synchronous poll. An
            // EOF or expired deadline still withholds its result, and the
            // consumed receipt forbids blind effect retries. A buffered
            // cancellation is only a notification: the session itself decides
            // whether its target is still owed a reply.
            frames.drain(input)?;
            if frames.eof {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(REFUSED.into());
            }
            if let Some(mut response) = response {
                response.push(b'\n');
                send(rpc, &mut frames, input, output, &response, deadline)?;
            }
        } else {
            let deadline = frames.deadline(rpc.deadline());
            if delivery.is_some() && frames.pending.is_empty() {
                // A periodic wake is not a grant expiry or a transport failure.
                wait_ready(input, None, deadline.min(next_tick), true)?;
            } else {
                wait(input, None, deadline)?;
            }
        }
    }
}

/// Serve a `private_outbox_status` long-poll: keep host delivery ticking and
/// answer as soon as the session reports a change, its deadline passes, or
/// no driver exists to change anything. EOF withholds the reply; a buffered
/// cancellation is handed to the session, which only clears a wait whose
/// exact request id it names and ignores every other target.
fn wait_for_change(
    runtime: &tokio::runtime::Runtime,
    rpc: &mut RpcSession,
    frames: &mut Frames,
    input: BorrowedFd<'_>,
    delivery: &mut Option<Driver>,
    next_tick: &mut Instant,
) -> Result<Option<Vec<u8>>, String> {
    loop {
        frames.drain(input)?;
        if frames.eof {
            return Ok(None);
        }
        while let Some(raw) = frames.take_cancellation() {
            // Cancellation notifications never carry a reply; a match clears
            // the pending wait so the loop returns with no frame.
            let _ = runtime.block_on(rpc.handle(&raw)).map_err(|_| REFUSED)?;
        }
        if let Some(driver) = delivery {
            if Instant::now() >= *next_tick {
                runtime.block_on(driver.tick(rpc))?;
                *next_tick = Instant::now() + Duration::from_secs(1);
                continue;
            }
        }
        if let Some(frame) = runtime
            .block_on(rpc.resume(delivery.is_none()))
            .map_err(|_| REFUSED)?
        {
            return Ok(Some(frame));
        }
        let Some(deadline) = rpc.waiting() else {
            return Ok(None);
        };
        let deadline = deadline.min(rpc.deadline());
        if delivery.is_some() {
            wait_ready(input, None, deadline.min(*next_tick), true)?;
        } else {
            wait_ready(input, None, deadline, true)?;
        }
    }
}

fn send(
    rpc: &mut RpcSession,
    frames: &mut Frames,
    input: BorrowedFd<'_>,
    output: BorrowedFd<'_>,
    bytes: &[u8],
    deadline: Instant,
) -> Result<(), String> {
    let mut offset = 0;
    while offset < bytes.len() {
        rpc.check_release().map_err(|_| REFUSED)?;
        frames.drain(input)?;
        if frames.eof {
            return Err(REFUSED.into());
        }
        let deadline = frames.deadline(deadline);
        if Instant::now() >= deadline {
            return Err(REFUSED.into());
        }
        match write(output, &bytes[offset..]) {
            Ok(0) => return Err(REFUSED.into()),
            Ok(n) => offset += n,
            Err(Errno::INTR) => continue,
            Err(Errno::AGAIN) => wait(input, Some(output), deadline)?,
            Err(_) => return Err(REFUSED.into()),
        }
        // A partial write may have disclosed a prefix already. Do not retry a
        // whole frame or renew authority; terminate and preserve all evidence.
        if Instant::now() >= deadline {
            return Err(REFUSED.into());
        }
    }
    rpc.check_release().map_err(|_| REFUSED)?;
    Ok(())
}

fn wait(
    input: BorrowedFd<'_>,
    output: Option<BorrowedFd<'_>>,
    deadline: Instant,
) -> Result<(), String> {
    wait_ready(input, output, deadline, false)
}

fn wait_ready(
    input: BorrowedFd<'_>,
    output: Option<BorrowedFd<'_>>,
    deadline: Instant,
    periodic: bool,
) -> Result<(), String> {
    loop {
        if periodic && Instant::now() >= deadline {
            return Ok(());
        }
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or(REFUSED)?;
        let timeout = Timespec::try_from(remaining).map_err(|_| REFUSED)?;
        let mut fds = vec![PollFd::from_borrowed_fd(input, PollFlags::IN)];
        if let Some(output) = output {
            fds.push(PollFd::from_borrowed_fd(output, PollFlags::OUT));
        }
        match poll(&mut fds, Some(&timeout)) {
            Ok(_) => {
                if (!periodic && Instant::now() >= deadline)
                    || fds
                        .iter()
                        .any(|fd| fd.revents().intersects(PollFlags::ERR | PollFlags::NVAL))
                {
                    return Err(REFUSED.into());
                }
                return Ok(());
            }
            Err(Errno::INTR) => continue,
            Err(_) => return Err(REFUSED.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{io::Write, os::unix::net::UnixStream};

    #[test]
    fn a_late_newline_cannot_renew_an_expired_partial_frame() {
        let (mut peer, input) = UnixStream::pair().unwrap();
        input.set_nonblocking(true).unwrap();
        peer.write_all(b"\n").unwrap();
        let mut frames = Frames {
            pending: b"{}".to_vec(),
            partial_deadline: Some(Instant::now() - Duration::from_secs(1)),
            ..Frames::default()
        };
        assert!(frames.drain(input.as_fd()).is_err());
        assert!(frames.ready.is_empty());
        assert_eq!(frames.pending, b"{}");
    }

    #[test]
    fn cancellation_detection_does_not_interpret_message_text() {
        assert!(is_cancellation(
            br#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1}}"#
        ));
        assert!(!is_cancellation(br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"arguments":{"body":"notifications/cancelled"}}}"#));
    }

    #[test]
    fn blank_lines_are_ignored() {
        let (mut peer, input) = UnixStream::pair().unwrap();
        input.set_nonblocking(true).unwrap();
        peer.write_all(b"\n\n\n").unwrap();
        let mut frames = Frames::default();
        frames.drain(input.as_fd()).unwrap();
        assert!(frames.ready.is_empty());
        assert!(frames.pending.is_empty());
        assert!(!frames.eof);
    }

    #[test]
    fn pipelined_frames_beyond_sixteen_are_buffered() {
        let (mut peer, input) = UnixStream::pair().unwrap();
        input.set_nonblocking(true).unwrap();
        let mut data = Vec::new();
        for _ in 0..20 {
            data.extend_from_slice(br#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#);
            data.push(b'\n');
        }
        peer.write_all(&data).unwrap();
        let mut frames = Frames::default();
        frames.drain(input.as_fd()).unwrap();
        assert_eq!(frames.ready.len(), 20);
        assert!(!frames.eof);
    }

    #[test]
    fn a_full_ready_queue_applies_backpressure_without_losing_frames() {
        let (mut peer, input) = UnixStream::pair().unwrap();
        input.set_nonblocking(true).unwrap();
        let mut data = Vec::new();
        for _ in 0..(MAX_READY + 5) {
            data.extend_from_slice(b"{}");
            data.push(b'\n');
        }
        peer.write_all(&data).unwrap();
        let mut frames = Frames::default();
        frames.drain(input.as_fd()).unwrap();
        assert_eq!(frames.ready.len(), MAX_READY);
        // Answering one frame frees a slot; the withheld bytes frame the next
        // request instead of being dropped or failing the transport.
        frames.ready.pop_front();
        frames.drain(input.as_fd()).unwrap();
        assert_eq!(frames.ready.len(), MAX_READY);
    }

    #[test]
    fn buffered_cancellation_is_consumed_not_fatal() {
        let (mut peer, input) = UnixStream::pair().unwrap();
        input.set_nonblocking(true).unwrap();
        peer.write_all(
            br#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1}}"#,
        )
        .unwrap();
        peer.write_all(b"\n").unwrap();
        let mut frames = Frames::default();
        frames.drain(input.as_fd()).unwrap();
        assert_eq!(frames.ready.len(), 1);
        assert!(frames.take_cancellation().is_some());
        assert!(frames.take_cancellation().is_none());
        assert!(!frames.eof);
    }
}
