//! Bridge to a persistent local ALGAL acceptor over a private Unix socket.
use super::{decode_frame, encode_frame, HabitatLinkError, HabitatLinkHandler, MAX_FRAME_BYTES};
use std::{
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Sends each envelope to an ALGAL socket adapter using the Habitat Link frame
/// format. The adapter verifies signed grants and owns execution and recovery.
/// No environment credential or Iroh peer identity is forwarded as authority.
/// Keep the socket in an owner-only directory. Each exchange has a ten-second
/// deadline, including connection establishment and the final EOF.
#[derive(Clone)]
pub struct UnixHabitatLinkHandler {
    path: PathBuf,
    timeout: Duration,
}

impl UnixHabitatLinkHandler {
    /// Select an absolute socket path. This does not connect or start ALGAL.
    pub fn new(path: impl AsRef<Path>) -> Result<Self, HabitatLinkError> {
        let path = path.as_ref();
        if !path.is_absolute() {
            return Err(HabitatLinkError::Handler);
        }
        Ok(Self {
            path: path.to_owned(),
            timeout: Duration::from_secs(10),
        })
    }

    async fn exchange(&self, frame: &[u8]) -> Result<Vec<u8>, HabitatLinkError> {
        let mut socket = tokio::net::UnixStream::connect(&self.path)
            .await
            .map_err(|_| HabitatLinkError::Handler)?;
        socket
            .write_all(frame)
            .await
            .map_err(|_| HabitatLinkError::Handler)?;
        let mut prefix = [0; 4];
        socket
            .read_exact(&mut prefix)
            .await
            .map_err(|_| HabitatLinkError::Truncated)?;
        let len = u32::from_be_bytes(prefix) as usize;
        if len == 0 {
            return Err(HabitatLinkError::Empty);
        }
        if len > MAX_FRAME_BYTES {
            return Err(HabitatLinkError::Oversize);
        }
        let mut reply = vec![0; len + 4];
        reply[..4].copy_from_slice(&prefix);
        socket
            .read_exact(&mut reply[4..])
            .await
            .map_err(|_| HabitatLinkError::Truncated)?;
        let mut trailing = [0];
        if socket
            .read(&mut trailing)
            .await
            .map_err(|_| HabitatLinkError::Handler)?
            != 0
        {
            return Err(HabitatLinkError::TrailingBytes);
        }
        decode_frame(&reply)
    }
}

impl HabitatLinkHandler for UnixHabitatLinkHandler {
    fn handle(&self, envelope: &[u8]) -> Result<Vec<u8>, HabitatLinkError> {
        let frame = encode_frame(envelope)?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| HabitatLinkError::Handler)?;
        runtime.block_on(async {
            tokio::time::timeout(self.timeout, self.exchange(&frame))
                .await
                .map_err(|_| HabitatLinkError::Timeout)?
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{Read, Write},
        os::unix::net::UnixListener,
        sync::atomic::{AtomicUsize, Ordering},
    };
    const REQUEST: &[u8] = br#"{"contract":"algal.habitat-query.v1","operationId":"0123456789abcdef0123456789abcdef"}"#;
    const REPLY: &[u8] = br#"{"contract":"algal.habitat-result.v1","operationId":"0123456789abcdef0123456789abcdef"}"#;
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    fn run(reply: Vec<u8>, delay: Duration) -> Result<Vec<u8>, HabitatLinkError> {
        let path = std::env::temp_dir().join(format!(
            "vhlink-{}-{}.sock",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let listener = UnixListener::bind(&path).unwrap();
        let worker = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut prefix = [0; 4];
            socket.read_exact(&mut prefix).unwrap();
            let len = u32::from_be_bytes(prefix) as usize;
            assert!(len <= MAX_FRAME_BYTES);
            let mut received = vec![0; len + 4];
            received[..4].copy_from_slice(&prefix);
            socket.read_exact(&mut received[4..]).unwrap();
            assert_eq!(decode_frame(&received).unwrap(), REQUEST);
            std::thread::sleep(delay);
            let _ = socket.write_all(&reply);
        });
        let mut handler = UnixHabitatLinkHandler::new(&path).unwrap();
        handler.timeout = Duration::from_millis(200);
        let result = handler.handle(REQUEST);
        worker.join().unwrap();
        std::fs::remove_file(path).unwrap();
        result
    }
    #[test]
    fn socket_bridge_round_trip() {
        assert_eq!(
            run(encode_frame(REPLY).unwrap(), Duration::ZERO).unwrap(),
            REPLY
        );
        assert!(UnixHabitatLinkHandler::new("relative.sock").is_err());
    }
    #[test]
    fn socket_bridge_refuses_invalid_replies() {
        assert_eq!(
            run(
                ((MAX_FRAME_BYTES + 1) as u32).to_be_bytes().to_vec(),
                Duration::ZERO
            ),
            Err(HabitatLinkError::Oversize)
        );
        assert_eq!(
            run(vec![0, 0, 0, 4, b'{'], Duration::ZERO),
            Err(HabitatLinkError::Truncated)
        );
        let mut extra = encode_frame(REPLY).unwrap();
        extra.push(0);
        assert_eq!(
            run(extra, Duration::ZERO),
            Err(HabitatLinkError::TrailingBytes)
        );
        assert_eq!(
            run(vec![], Duration::ZERO),
            Err(HabitatLinkError::Truncated)
        );
    }
    #[test]
    fn socket_bridge_times_out() {
        assert_eq!(
            run(encode_frame(REPLY).unwrap(), Duration::from_millis(300)),
            Err(HabitatLinkError::Timeout)
        );
    }
}
