#![forbid(unsafe_code)]
//! Disposable loopback-only transport experiment. Fixture keys are public;
//! this authenticates transport PeerIds, never Valhalla application authority.

use std::{error::Error, io, io::Write, num::NonZeroU8, time::Duration};

use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, StreamExt};
use libp2p::{
    Multiaddr, PeerId, StreamProtocol, Swarm, SwarmBuilder,
    allow_block_list::{self, AllowedPeers},
    connection_limits::{self, ConnectionLimits},
    identity::Keypair,
    multiaddr::Protocol,
    request_response::{self, ProtocolSupport},
    swarm::{DialError, NetworkBehaviour, SwarmEvent},
};

const MAX_FRAME: usize = 64 * 1024;
const DEADLINE: Duration = Duration::from_secs(10);
// One fixture listener serves three independently bounded sender processes.
const LISTENER_LIFETIME: Duration = Duration::from_secs(60);
const PROTOCOL: StreamProtocol = StreamProtocol::new("/vhalla/opaque-echo-spike/1");
type Result<T> = std::result::Result<T, Box<dyn Error>>;

#[derive(Clone, Default)]
struct BoundedCodec;

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

#[derive(NetworkBehaviour)]
struct Network {
    // Admission must run before request-response preloads connection state.
    allowed: allow_block_list::Behaviour<AllowedPeers>,
    limits: connection_limits::Behaviour,
    echo: request_response::Behaviour<BoundedCodec>,
}

fn key(seed: u8) -> Keypair {
    Keypair::ed25519_from_bytes([seed; 32]).expect("32-byte fixture key")
}

fn network(seed: u8, expected: PeerId) -> Result<Swarm<Network>> {
    let mut allowed = allow_block_list::Behaviour::<AllowedPeers>::default();
    allowed.allow_peer(expected);
    let limits = ConnectionLimits::default()
        .with_max_pending_incoming(Some(4))
        .with_max_pending_outgoing(Some(4))
        .with_max_established(Some(4))
        .with_max_established_per_peer(Some(1));
    let behaviour = Network {
        echo: request_response::Behaviour::with_codec(
            BoundedCodec,
            [(PROTOCOL, ProtocolSupport::Full)],
            request_response::Config::default()
                .with_request_timeout(DEADLINE)
                .with_max_concurrent_streams(4),
        ),
        limits: connection_limits::Behaviour::new(limits),
        allowed,
    };
    Ok(SwarmBuilder::with_existing_identity(key(seed))
        .with_tokio()
        .with_quic_config(|mut config| {
            config.handshake_timeout = DEADLINE;
            config.max_idle_timeout = 10_000;
            config.max_concurrent_stream_limit = 4;
            config.max_stream_data = (MAX_FRAME + 1024) as u32;
            config.max_connection_data = ((MAX_FRAME + 1024) * 4) as u32;
            config
        })
        .with_behaviour(|_| behaviour)?
        .with_swarm_config(|config| {
            config
                .with_idle_connection_timeout(DEADLINE)
                .with_per_connection_event_buffer_size(4)
                .with_dial_concurrency_factor(NonZeroU8::new(1).unwrap())
        })
        .build())
}

fn invitation(text: &str) -> Result<(Multiaddr, PeerId)> {
    // This deliberately scoped spike cannot dial arbitrary public targets.
    if text.len() > 256 {
        return Err("invitation too long".into());
    }
    let address: Multiaddr = text.parse()?;
    let parts: Vec<_> = address.iter().collect();
    let expected = match parts.as_slice() {
        [
            Protocol::Ip4(ip),
            Protocol::Udp(port),
            Protocol::QuicV1,
            Protocol::P2p(peer),
        ] if ip.is_loopback() && *port != 0 => *peer,
        _ => return Err("expected loopback /ip4/.../udp/.../quic-v1/p2p/<expected-peer>".into()),
    };
    Ok((address, expected))
}

fn log(message: &str) {
    println!("{message}");
    io::stdout().flush().expect("stdout");
}

async fn listen(seed: u8, expected: PeerId) -> Result<()> {
    let mut swarm = network(seed, expected)?;
    swarm.listen_on("/ip4/127.0.0.1/udp/0/quic-v1".parse()?)?;
    let stop = tokio::time::sleep(LISTENER_LIFETIME);
    tokio::pin!(stop);
    loop {
        tokio::select! {
            _ = &mut stop => return Err("listener fixture lifetime expired".into()),
            event = swarm.select_next_some() => match event {
                SwarmEvent::NewListenAddr { address, .. } => {
                    log(&format!("INVITE {address}/p2p/{}", swarm.local_peer_id()));
                    log(&format!("LISTENER_PID {}", std::process::id()));
                }
                SwarmEvent::Behaviour(NetworkEvent::Echo(request_response::Event::Message {
                    peer, message: request_response::Message::Request { request, channel, .. }, ..
                })) => {
                    if peer != expected { return Err("unexpected inbound peer".into()); }
                    log(&format!("ECHO bytes={} peer={peer}", request.len()));
                    swarm.behaviour_mut().echo.send_response(channel, request)
                        .map_err(|_| "response channel closed")?;
                }
                SwarmEvent::Behaviour(NetworkEvent::Echo(request_response::Event::InboundFailure { error, .. })) => {
                    log(&format!("INBOUND_REJECTED {error}"));
                }
                SwarmEvent::ListenerError { error, .. } => return Err(error.into()),
                SwarmEvent::ConnectionClosed { peer_id, .. } => log(&format!("PEER_CLOSED {peer_id}")),
                _ => {}
            }
        }
    }
}

async fn send(seed: u8, address: &str, payload: Vec<u8>) -> Result<()> {
    if payload.len() > MAX_FRAME {
        return Err("oversized payload".into());
    }
    let (address, expected) = invitation(address)?;
    let mut swarm = network(seed, expected)?;
    swarm.dial(address)?;
    let mut sent = false;
    let mut completed = false;
    let stop = tokio::time::sleep(DEADLINE);
    tokio::pin!(stop);
    loop {
        tokio::select! {
            _ = &mut stop => return Err("sender 10-second deadline".into()),
            event = swarm.select_next_some() => match event {
                SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                    if peer_id != expected { return Err("unexpected transport peer".into()); }
                    if !sent {
                        log(&format!("SENDER_PID {}", std::process::id()));
                        swarm.behaviour_mut().echo.send_request(&expected, payload.clone());
                        sent = true;
                    }
                }
                SwarmEvent::Behaviour(NetworkEvent::Echo(request_response::Event::Message {
                    peer, message: request_response::Message::Response { response, .. }, ..
                })) => {
                    if peer != expected || response != payload { return Err("echo mismatch".into()); }
                    log(&format!("ECHO_OK bytes={} peer={peer}", response.len()));
                    completed = true;
                    swarm.disconnect_peer_id(peer).map_err(|_| "peer already disconnected")?;
                }
                SwarmEvent::ConnectionClosed { peer_id, .. } if completed && peer_id == expected => {
                    // Let Quinn's runtime flush its close datagram after the
                    // swarm releases the connection. The runner separately
                    // requires the listener to observe PEER_CLOSED.
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    return Ok(());
                }
                SwarmEvent::OutgoingConnectionError { error, .. } => {
                    if matches!(error, DialError::WrongPeerId { .. }) {
                        return Err(format!("WRONG_PEER_REJECTED {error}").into());
                    }
                    return Err(format!("DIAL_REJECTED {error}").into());
                }
                SwarmEvent::Behaviour(NetworkEvent::Echo(request_response::Event::OutboundFailure { error, .. })) => {
                    return Err(error.into());
                }
                _ => {}
            }
        }
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let result: Result<()> = async {
        let mut args = std::env::args().skip(1);
        let mode = args.next().ok_or("mode: peer-id | listen | send")?;
        let seed: u8 = args.next().ok_or("missing fixture seed byte")?.parse()?;
        match mode.as_str() {
            "peer-id" => log(&key(seed).public().to_peer_id().to_string()),
            "listen" => {
                listen(
                    seed,
                    args.next().ok_or("missing expected sender peer")?.parse()?,
                )
                .await?
            }
            "send" => {
                let address = args.next().ok_or("missing invitation")?;
                let length: usize = args.next().ok_or("missing payload length")?.parse()?;
                if length > MAX_FRAME {
                    return Err("oversized payload".into());
                }
                let payload: Vec<_> = (0..length).map(|i| (i % 251) as u8).collect();
                send(seed, &address, payload).await?;
            }
            _ => return Err("unknown mode".into()),
        }
        Ok(())
    }
    .await;
    if let Err(error) = result {
        eprintln!("{error}");
        std::process::exit(2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::io::Cursor;

    #[test]
    fn bounded_binary_roundtrip_including_limit() {
        for size in [0, 1, 17, MAX_FRAME] {
            let payload = vec![0xa5; size];
            let mut stream = Cursor::new(Vec::new());
            futures::executor::block_on(write_frame(&mut stream, &payload)).unwrap();
            stream.set_position(0);
            assert_eq!(
                futures::executor::block_on(read_frame(&mut stream)).unwrap(),
                payload
            );
        }
    }

    #[test]
    fn oversize_is_rejected_from_header_before_body_read() {
        // No body exists. Reading one would instead return UnexpectedEof.
        for length in [MAX_FRAME as u32 + 1, u32::MAX] {
            let mut stream = Cursor::new(length.to_be_bytes());
            let error = futures::executor::block_on(read_frame(&mut stream)).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            assert_eq!(stream.position(), 4);
        }
    }

    #[test]
    fn truncated_and_trailing_data_are_rejected() {
        for bytes in [vec![], vec![0, 0, 0, 2, 1], vec![0, 0, 0, 0, 1]] {
            assert!(futures::executor::block_on(read_frame(&mut Cursor::new(bytes))).is_err());
        }
        let mut sink = Cursor::new(Vec::new());
        assert!(
            futures::executor::block_on(write_frame(&mut sink, &vec![0; MAX_FRAME + 1])).is_err()
        );
        assert!(sink.into_inner().is_empty());
    }

    #[test]
    fn invitation_requires_loopback_quic_and_expected_peer() {
        let peer = key(1).public().to_peer_id();
        assert!(invitation(&format!("/ip4/127.0.0.1/udp/1/quic-v1/p2p/{peer}")).is_ok());
        for address in [
            "/ip4/127.0.0.1/udp/1/quic-v1".to_string(),
            format!("/ip4/8.8.8.8/udp/1/quic-v1/p2p/{peer}"),
            format!("/ip4/127.0.0.1/udp/0/quic-v1/p2p/{peer}"),
        ] {
            assert!(invitation(&address).is_err());
        }
    }
}
