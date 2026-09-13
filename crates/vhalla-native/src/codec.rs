//! Length admission precedes allocation. One request occupies one stream.
use super::MAX_FRAME;
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::{request_response, StreamProtocol};
use std::io;

#[derive(Clone, Default)]
pub(crate) struct BoundedCodec;

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
    io.write_all(body).await?;
    io.close().await
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
    use proptest::prelude::*;
    #[test]
    fn max_frame_and_oversize_before_read_or_write() {
        let mut io = Cursor::new(Vec::new());
        block_on(write_frame(&mut io, &vec![42; MAX_FRAME])).unwrap();
        io.set_position(0);
        assert_eq!(block_on(read_frame(&mut io)).unwrap(), vec![42; MAX_FRAME]);
        for n in [MAX_FRAME as u32 + 1, u32::MAX] {
            let mut io = Cursor::new(n.to_be_bytes());
            assert_eq!(
                block_on(read_frame(&mut io)).unwrap_err().kind(),
                std::io::ErrorKind::InvalidData
            );
            assert_eq!(io.position(), 4);
        }
        let mut io = Cursor::new(Vec::new());
        assert!(block_on(write_frame(&mut io, &vec![0; MAX_FRAME + 1])).is_err());
        assert!(io.into_inner().is_empty());
    }
    proptest! {
        #[test]
        fn bounded_roundtrip_and_trailing_rejection(body in prop::collection::vec(any::<u8>(), 0..4096)) {
            let mut io = Cursor::new(Vec::new());
            block_on(write_frame(&mut io, &body)).unwrap();
            io.set_position(0);
            prop_assert_eq!(block_on(read_frame(&mut io)).unwrap(), body);
            let mut raw = io.into_inner();
            raw.push(0);
            prop_assert!(block_on(read_frame(&mut Cursor::new(raw))).is_err());
        }
        #[test]
        fn arbitrary_frame_never_panics(raw in prop::collection::vec(any::<u8>(), 0..4096)) {
            if let Ok(body) = block_on(read_frame(&mut Cursor::new(raw))) {
                prop_assert!(body.len() <= MAX_FRAME);
            }
        }
    }
}
