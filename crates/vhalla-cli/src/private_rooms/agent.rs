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
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let input = stdin.as_fd();
    let output = stdout.as_fd();
    // Actual stdio peers only: never print plaintext to a terminal or silently
    // reuse the ordinary CLI's success banner / unbounded file redirection.
    for fd in [input, output] {
        if !matches!(
            FileType::from_raw_mode(fstat(fd).map_err(|_| REFUSED)?.st_mode),
            FileType::Fifo | FileType::Socket
        ) {
            return Err(HELP.into());
        }
    }
    let _input_flags = Nonblocking::new(input)?;
    let _output_flags = Nonblocking::new(output)?;
    let bytes = files::read(Path::new(&raw[5]), MAX_GRANT_BYTES, false)?;
    let launch = LaunchGrant::decode(&bytes).map_err(|_| REFUSED)?;
    let context = launch.context();
    let identity = Identity::open(Path::new(&raw[2])).map_err(|_| REFUSED)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .map_err(|_| REFUSED)?;
    let room = runtime
        .block_on(RoomSession::open(identity, Path::new(&raw[3]), context))
        .map_err(|_| REFUSED)?;
    // Open the independently selected host profile before consuming a grant.
    // This performs no network effect and refuses absent/foreign state.
    let mut delivery = if raw.len() == 8 {
        Some(Driver::open(Path::new(&raw[7]), context)?)
    } else {
        None
    };
    let mut rpc = RpcSession::new(room, launch).map_err(|_| REFUSED)?;
    let result = serve(&runtime, &mut rpc, input, output, &mut delivery);
    rpc.revoke();
    result
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

#[derive(Default)]
struct Frames {
    pending: Vec<u8>,
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
            let received = read(input, &mut buffer);
            self.check_deadline()?;
            match received {
                Ok(0) => {
                    self.eof = true;
                    return Ok(());
                }
                Ok(n) => {
                    for byte in &buffer[..n] {
                        if *byte == b'\n' {
                            // Readiness and a final read do not extend the
                            // deadline if this process was descheduled.
                            self.check_deadline()?;
                            if self.pending.is_empty() || self.ready.len() >= 16 {
                                return Err(REFUSED.into());
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
                            self.pending.push(*byte);
                        }
                    }
                }
                Err(Errno::INTR) => continue,
                Err(Errno::AGAIN) => return Ok(()),
                Err(_) => return Err(REFUSED.into()),
            }
        }
    }
    fn cancelled(&self) -> bool {
        self.ready.iter().any(|raw| is_cancellation(raw))
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
        if frames.eof || frames.cancelled() {
            return Ok(());
        }
        if frames.pending.is_empty() && Instant::now() >= next_tick {
            if let Some(driver) = delivery {
                runtime.block_on(driver.tick(rpc))?;
                frames.drain(input)?;
                if frames.eof || frames.cancelled() {
                    return Ok(());
                }
                rpc.check_release().map_err(|_| REFUSED)?;
            }
            next_tick = Instant::now() + Duration::from_secs(1);
        }
        if let Some(raw) = frames.ready.pop_front() {
            let deadline = (Instant::now() + IO_DEADLINE).min(rpc.deadline());
            let response = runtime.block_on(rpc.handle(&raw)).map_err(|_| REFUSED)?;
            // Native custody I/O may complete inside one synchronous poll. A
            // buffered cancellation/EOF or expired deadline still withholds its
            // result, and the consumed receipt forbids blind effect retries.
            frames.drain(input)?;
            if frames.eof || frames.cancelled() {
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
        if frames.eof || frames.cancelled() {
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
}
