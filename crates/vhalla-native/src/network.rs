use super::*;
use codec::BoundedCodec;
use libp2p::{
    allow_block_list::{self, AllowedPeers},
    connection_limits::{self, ConnectionLimits},
    identity::Keypair,
    request_response::{self, ProtocolSupport},
    swarm::{behaviour::toggle::Toggle, NetworkBehaviour},
    StreamProtocol, Swarm, SwarmBuilder,
};
use std::num::NonZeroU8;
use zeroize::Zeroizing;

#[derive(NetworkBehaviour)]
pub(crate) struct Network {
    pub(crate) chat: request_response::Behaviour<BoundedCodec>,
    limits: connection_limits::Behaviour,
    allowed: Toggle<allow_block_list::Behaviour<AllowedPeers>>,
}

pub(crate) fn new(expected: Option<PeerId>) -> Result<Swarm<Network>> {
    let mut seed = Zeroizing::new([0; 32]);
    getrandom::fill(seed.as_mut()).map_err(|_| Error::Input("OS transport entropy failed"))?;
    let key = Keypair::ed25519_from_bytes(seed.as_mut()).map_err(transport)?;
    let allowed = expected.map(|peer| {
        let mut allowed = allow_block_list::Behaviour::<AllowedPeers>::default();
        allowed.allow_peer(peer);
        allowed
    });
    let behaviour = Network {
        chat: request_response::Behaviour::with_codec(
            BoundedCodec,
            [(
                StreamProtocol::new("/vhalla/paired-chat/1"),
                ProtocolSupport::Full,
            )],
            request_response::Config::default()
                .with_request_timeout(REQUEST_DEADLINE)
                .with_max_concurrent_streams(4),
        ),
        limits: connection_limits::Behaviour::new(
            ConnectionLimits::default()
                .with_max_pending_incoming(Some(MAX_CONNECTIONS))
                .with_max_pending_outgoing(Some(MAX_CONNECTIONS))
                .with_max_established(Some(MAX_CONNECTIONS))
                .with_max_established_per_peer(Some(1)),
        ),
        allowed: allowed.into(),
    };
    Ok(SwarmBuilder::with_existing_identity(key)
        .with_tokio()
        .with_quic_config(|mut config| {
            config.handshake_timeout = HANDSHAKE_DEADLINE;
            config.max_idle_timeout = 10_000;
            config.max_concurrent_stream_limit = 4;
            config.max_stream_data = (MAX_FRAME + 1024) as u32;
            config.max_connection_data = ((MAX_FRAME + 1024) * 4) as u32;
            config
        })
        .with_behaviour(|_| behaviour)
        .map_err(transport)?
        .with_swarm_config(|config| {
            config
                .with_idle_connection_timeout(REQUEST_DEADLINE)
                .with_per_connection_event_buffer_size(4)
                .with_dial_concurrency_factor(NonZeroU8::new(1).expect("nonzero"))
        })
        .build())
}
