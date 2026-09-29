//! Loopback qualification of the dedicated Habitat Link handler. Every test
//! binds direct-only endpoints on 127.0.0.1 with no relay and no discovery.
use super::*;
use ::iroh::{
    endpoint::{ApplicationClose, ConnectionError, ReadError, ReadToEndError, VarInt},
    Endpoint, EndpointAddr, SecretKey,
};
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc,
};
use std::time::{Duration, Instant};

const OPERATION: &str = "0123456789abcdef0123456789abcdef";

fn invocation() -> Vec<u8> {
    format!(r#"{{"contract":"algal.habitat-invocation.v1","operationId":"{OPERATION}"}}"#).into()
}

/// A habitat stand-in: acknowledge the invocation it received.
fn echo_acceptance(calls: Arc<AtomicUsize>) -> impl HabitatLinkHandler {
    move |envelope: &[u8]| {
        calls.fetch_add(1, Ordering::AcqRel);
        let value: serde_json::Value =
            serde_json::from_slice(envelope).map_err(|_| HabitatLinkError::InvalidJson)?;
        let id = value["operationId"]
            .as_str()
            .ok_or(HabitatLinkError::InvalidOperationId)?;
        Ok(format!(r#"{{"contract":"algal.habitat-acceptance.v1","operationId":"{id}"}}"#).into())
    }
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
}

async fn bind_host(secret: u8, alpns: Vec<Vec<u8>>) -> (Endpoint, EndpointAddr) {
    let endpoint = endpoint_builder(None)
        .unwrap()
        .secret_key(SecretKey::from_bytes(&[secret; 32]))
        .alpns(alpns)
        .clear_ip_transports()
        .bind_addr("127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap())
        .unwrap()
        .bind()
        .await
        .unwrap();
    let mut addr = EndpointAddr::new(endpoint.id());
    for ip in endpoint.addr().ip_addrs() {
        addr = addr.with_ip_addr(*ip);
    }
    assert!(addr.ip_addrs().next().is_some());
    (endpoint, addr)
}

async fn bind_client() -> Endpoint {
    endpoint_builder(None).unwrap().bind().await.unwrap()
}

struct Host {
    endpoint: Endpoint,
    addr: EndpointAddr,
    stop: Arc<AtomicBool>,
    serving: Option<tokio::task::JoinHandle<Result<(), HabitatLinkError>>>,
}

impl Host {
    async fn start(service: HabitatLinkService) -> Self {
        let (endpoint, addr) = bind_host(2, vec![HABITAT_LINK_ALPN.to_vec()]).await;
        let stop = Arc::new(AtomicBool::new(false));
        let serving = {
            let (endpoint, stop) = (endpoint.clone(), stop.clone());
            tokio::spawn(async move { service.serve(&endpoint, stop).await })
        };
        Self {
            endpoint,
            addr,
            stop,
            serving: Some(serving),
        }
    }
    async fn stop(mut self) {
        self.stop.store(true, Ordering::Release);
        tokio::time::timeout(Duration::from_secs(10), self.serving.take().unwrap())
            .await
            .expect("serve loop stops promptly")
            .unwrap()
            .unwrap();
        self.endpoint.close().await;
    }
}

#[test]
fn loopback_invocation_receives_acceptance_from_the_habitat_handler() {
    runtime().block_on(async {
        let calls = Arc::new(AtomicUsize::new(0));
        let service = HabitatLinkService::new(echo_acceptance(calls.clone()));
        let host = Host::start(service.clone()).await;
        let client = bind_client().await;
        let reply = tokio::time::timeout(
            Duration::from_secs(20),
            send_envelope(&client, host.addr.clone(), &invocation()),
        )
        .await
        .expect("exchange within bound")
        .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&reply).unwrap();
        assert_eq!(value["contract"], "algal.habitat-acceptance.v1");
        assert_eq!(value["operationId"], OPERATION);
        assert_eq!(calls.load(Ordering::Acquire), 1);
        // A second exchange on a fresh connection uses a fresh stream.
        send_envelope(&client, host.addr.clone(), &invocation())
            .await
            .unwrap();
        assert_eq!(calls.load(Ordering::Acquire), 2);
        // Invalid envelopes are refused locally before any connection opens.
        assert_eq!(
            send_envelope(&client, host.addr.clone(), br#"{"contract":"future.v9"}"#).await,
            Err(HabitatLinkError::UnsupportedContract)
        );
        assert_eq!(calls.load(Ordering::Acquire), 2);
        // The host releases each stream slot once its reply is acknowledged.
        let released = Instant::now() + Duration::from_secs(5);
        while service.live_streams() != 0 {
            assert!(Instant::now() < released, "stream slots were not released");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        client.close().await;
        host.stop().await;
    });
}

#[test]
fn oversize_declared_length_is_refused_before_any_payload_is_read() {
    runtime().block_on(async {
        let calls = Arc::new(AtomicUsize::new(0));
        let host = Host::start(HabitatLinkService::new(echo_acceptance(calls.clone()))).await;
        let client = bind_client().await;
        let connection = client
            .connect(host.addr.clone(), HABITAT_LINK_ALPN)
            .await
            .unwrap();
        let (mut send, mut recv) = connection.open_bi().await.unwrap();
        // Declare one byte over the bound and send nothing else; the stream is
        // left open so a handler that buffered first would wait for payload.
        let declared = u32::try_from(MAX_FRAME_BYTES + 1).unwrap();
        send.write_all(&declared.to_be_bytes()).await.unwrap();
        let stopped = tokio::time::timeout(Duration::from_secs(5), send.stopped())
            .await
            .expect("refusal arrives before the read timeout")
            .unwrap();
        assert_eq!(stopped, Some(VarInt::from_u32(STOP_FRAME_REJECTED)));
        let reply = tokio::time::timeout(Duration::from_secs(5), recv.read_to_end(8))
            .await
            .unwrap();
        assert!(reply.is_err(), "no reply frame is written: {reply:?}");
        connection.close(VarInt::from_u32(0), b"done");
        // A frame that ends before its declared length is also refused.
        let connection = client
            .connect(host.addr.clone(), HABITAT_LINK_ALPN)
            .await
            .unwrap();
        let (mut send, mut recv) = connection.open_bi().await.unwrap();
        send.write_all(&[0, 0, 0, 16, b'{']).await.unwrap();
        send.finish().unwrap();
        // A finished stream is acknowledged before it is stopped, so the
        // refusal is observed on the reset reply stream instead.
        let reply = tokio::time::timeout(Duration::from_secs(5), recv.read_to_end(8))
            .await
            .unwrap();
        assert!(
            matches!(
                reply,
                Err(ReadToEndError::Read(ReadError::Reset(code)))
                    if code == VarInt::from_u32(STOP_FRAME_REJECTED)
            ),
            "{reply:?}"
        );
        connection.close(VarInt::from_u32(0), b"done");
        assert_eq!(calls.load(Ordering::Acquire), 0);
        // The host still serves a well-formed request afterwards.
        send_envelope(&client, host.addr.clone(), &invocation())
            .await
            .unwrap();
        assert_eq!(calls.load(Ordering::Acquire), 1);
        client.close().await;
        host.stop().await;
    });
}

#[test]
fn connections_on_another_alpn_are_closed_without_reaching_the_handler() {
    runtime().block_on(async {
        let calls = Arc::new(AtomicUsize::new(0));
        let service = HabitatLinkService::new(echo_acceptance(calls.clone()));
        let other = b"vhalla-test/other/1".to_vec();
        let (host, addr) = bind_host(2, vec![HABITAT_LINK_ALPN.to_vec(), other.clone()]).await;
        let accepting = {
            let (host, service) = (host.clone(), service.clone());
            tokio::spawn(async move {
                let incoming = host.accept().await.unwrap();
                let connection = incoming.await.unwrap();
                assert_eq!(connection.alpn(), other.as_slice());
                service.serve_connection(connection).await
            })
        };
        let client = bind_client().await;
        let connection = client
            .connect(addr.clone(), b"vhalla-test/other/1")
            .await
            .unwrap();
        let closed = tokio::time::timeout(Duration::from_secs(5), connection.closed())
            .await
            .unwrap();
        assert!(
            matches!(
                closed,
                ConnectionError::ApplicationClosed(ApplicationClose { error_code, .. })
                    if error_code == VarInt::from_u32(CLOSE_WRONG_ALPN)
            ),
            "{closed:?}"
        );
        assert_eq!(accepting.await.unwrap(), Err(HabitatLinkError::WrongAlpn));
        assert_eq!(calls.load(Ordering::Acquire), 0);
        // The dedicated serve loop advertises only the Habitat Link ALPN, so a
        // peer on another ALPN cannot even complete its handshake there.
        let stop = Arc::new(AtomicBool::new(false));
        let serving = {
            let (host, stop) = (host.clone(), stop.clone());
            tokio::spawn(async move { service.serve(&host, stop).await })
        };
        let refused = tokio::time::timeout(
            Duration::from_secs(10),
            client.connect(addr.clone(), b"vhalla-test/other/1"),
        )
        .await
        .unwrap();
        assert!(refused.is_err());
        assert_eq!(calls.load(Ordering::Acquire), 0);
        stop.store(true, Ordering::Release);
        serving.await.unwrap().unwrap();
        client.close().await;
        host.close().await;
    });
}

#[test]
fn handler_refusals_reset_the_stream_without_a_reply_frame() {
    runtime().block_on(async {
        let service = HabitatLinkService::new(|_envelope: &[u8]| Err(HabitatLinkError::Handler));
        let host = Host::start(service).await;
        let client = bind_client().await;
        let connection = client
            .connect(host.addr.clone(), HABITAT_LINK_ALPN)
            .await
            .unwrap();
        let (mut send, mut recv) = connection.open_bi().await.unwrap();
        send.write_all(&encode_frame(&invocation()).unwrap())
            .await
            .unwrap();
        send.finish().unwrap();
        let reply = tokio::time::timeout(Duration::from_secs(5), recv.read_to_end(8))
            .await
            .unwrap();
        assert!(reply.is_err(), "{reply:?}");
        connection.close(VarInt::from_u32(0), b"done");
        assert_eq!(
            send_envelope(&client, host.addr.clone(), &invocation()).await,
            Err(HabitatLinkError::Connection)
        );
        client.close().await;
        host.stop().await;
    });
}
