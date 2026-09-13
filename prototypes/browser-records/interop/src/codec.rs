//! Length admission precedes allocation. One request occupies one stream.
use super::MAX_FRAME;
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::{StreamProtocol, request_response};
use std::io;

#[derive(Clone, Default)]
pub struct BoundedCodec;

async fn read_frame<T: AsyncRead + Unpin>(io: &mut T) -> io::Result<Vec<u8>> {
    let mut header = [0_u8; 4];
    io.read_exact(&mut header).await?;
    let length = u32::from_be_bytes(header) as usize;
    if length > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "oversized frame",
        ));
    }
    // The untrusted length is checked before any payload allocation or read.
    #[cfg(target_arch = "wasm32")]
    if super::PAUSE.load(std::sync::atomic::Ordering::Relaxed) {
        futures_timer::Delay::new(std::time::Duration::from_millis(100)).await;
    }
    let mut body = vec![0; length];
    io.read_exact(&mut body).await?;
    let mut extra = [0_u8; 1];
    if io.read(&mut extra).await? != 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "trailing bytes"));
    }
    Ok(body)
}

async fn write_frame<T: AsyncWrite + Unpin>(io: &mut T, body: &[u8]) -> io::Result<()> {
    if body.len() > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "oversized frame",
        ));
    }
    io.write_all(&(body.len() as u32).to_be_bytes()).await?;
    io.flush().await?;
    for chunk in body.chunks(1024) {
        io.write_all(chunk).await?;
        io.flush().await?;
    }
    // request-response closes after the codec returns. A second close fails on
    // WebRTC's BothClosed state even though the response bytes were delivered.
    io.flush().await
}

impl request_response::Codec for BoundedCodec {
    type Protocol = StreamProtocol;
    type Request = Vec<u8>;
    type Response = Vec<u8>;

    async fn read_request<T>(&mut self, _: &StreamProtocol, io: &mut T) -> io::Result<Vec<u8>>
    where
        T: AsyncRead + Unpin + Send,
    {
        read_frame(io).await
    }
    async fn read_response<T>(&mut self, _: &StreamProtocol, io: &mut T) -> io::Result<Vec<u8>>
    where
        T: AsyncRead + Unpin + Send,
    {
        read_frame(io).await
    }
    async fn write_request<T>(
        &mut self,
        _: &StreamProtocol,
        io: &mut T,
        body: Vec<u8>,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        write_frame(io, &body).await
    }
    async fn write_response<T>(
        &mut self,
        _: &StreamProtocol,
        io: &mut T,
        body: Vec<u8>,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        write_frame(io, &body).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::{executor::block_on, io::Cursor};
    use std::{
        pin::Pin,
        task::{Context, Poll},
    };

    #[test]
    fn bounded_codec_rejects_length_before_payload_read_or_write() {
        for length in [MAX_FRAME as u32 + 1, u32::MAX] {
            let mut input = Cursor::new(length.to_be_bytes());
            assert_eq!(
                block_on(read_frame(&mut input)).unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
            assert_eq!(input.position(), 4);
        }
        let mut output = Cursor::new(Vec::new());
        assert!(block_on(write_frame(&mut output, &vec![0; MAX_FRAME + 1])).is_err());
        assert!(output.into_inner().is_empty());
    }

    #[test]
    fn boundary_roundtrip_truncation_and_trailing_rejection() {
        for length in [0, 1, 44, MAX_FRAME] {
            let body = vec![7; length];
            let mut output = Cursor::new(Vec::new());
            block_on(write_frame(&mut output, &body)).unwrap();
            output.set_position(0);
            assert_eq!(block_on(read_frame(&mut output)).unwrap(), body);
            let mut raw = output.into_inner();
            raw.push(0);
            assert!(block_on(read_frame(&mut Cursor::new(raw))).is_err());
        }
        for raw in [vec![], vec![0, 0, 0, 2, 1]] {
            assert!(block_on(read_frame(&mut Cursor::new(raw))).is_err());
        }
    }

    // WebRTC permits one graceful close after both halves finish. Model that
    // transport contract while exercising the actual request-response codec.
    struct OneClose {
        closed: bool,
    }
    impl AsyncWrite for OneClose {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            assert!(!self.closed);
            Poll::Ready(Ok(bytes.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_close(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            if self.closed {
                return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
            }
            self.closed = true;
            Poll::Ready(Ok(()))
        }
    }
    #[test]
    fn framework_can_close_once_after_codec_returns() {
        use request_response::Codec;
        let mut codec = BoundedCodec;
        let mut io = OneClose { closed: false };
        block_on(codec.write_response(&StreamProtocol::new("/fixture/1"), &mut io, vec![1]))
            .unwrap();
        // libp2p-request-response's handler performs this exact final operation.
        block_on(io.close()).unwrap();
    }
}
