#![forbid(unsafe_code)]
use libp2p::{
    PeerId, StreamProtocol,
    allow_block_list::{self, AllowedPeers},
    connection_limits::{self, ConnectionLimits},
    identity::Keypair,
    request_response::{self, ProtocolSupport},
    swarm::NetworkBehaviour,
};
use std::time::Duration;
mod codec;
const MAX_FRAME: usize = vhalla_browser_records_spike::MAX_RECORD;
pub fn key(seed: u8) -> Keypair {
    Keypair::ed25519_from_bytes([seed; 32]).unwrap()
}
#[derive(NetworkBehaviour)]
pub struct Network {
    allowed: allow_block_list::Behaviour<AllowedPeers>,
    limits: connection_limits::Behaviour,
    pub echo: request_response::Behaviour<codec::BoundedCodec>,
}
pub fn behaviour(peer: PeerId) -> Network {
    let mut allowed = allow_block_list::Behaviour::<AllowedPeers>::default();
    allowed.allow_peer(peer);
    Network {
        echo: request_response::Behaviour::with_codec(
            codec::BoundedCodec,
            [(
                StreamProtocol::new("/vhalla/webrtc-record-spike/1"),
                ProtocolSupport::Full,
            )],
            request_response::Config::default()
                .with_request_timeout(Duration::from_secs(10))
                .with_max_concurrent_streams(4),
        ),
        limits: connection_limits::Behaviour::new(
            ConnectionLimits::default()
                .with_max_pending_incoming(Some(4))
                .with_max_pending_outgoing(Some(4))
                .with_max_established(Some(4))
                .with_max_established_per_peer(Some(1)),
        ),
        allowed,
    }
}
#[cfg(target_arch = "wasm32")]
static PAUSE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
#[cfg(target_arch = "wasm32")]
mod browser;
