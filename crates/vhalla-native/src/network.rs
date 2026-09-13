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
    // Derive invokes admission hooks in declaration order. Request-response
    // 0.30 preloads state in its hook, before the swarm confirms admission.
    // Every rejecting behaviour must precede it, or denials leak connections.
    allowed: Toggle<allow_block_list::Behaviour<AllowedPeers>>,
    limits: connection_limits::Behaviour,
    pub(crate) chat: request_response::Behaviour<BoundedCodec>,
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

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::{
        core::ConnectedPoint,
        swarm::{
            behaviour::{ConnectionClosed, ConnectionEstablished},
            ConnectionId, FromSwarm,
        },
    };
    fn peer(seed: u8) -> PeerId {
        Keypair::ed25519_from_bytes([seed; 32])
            .unwrap()
            .public()
            .to_peer_id()
    }

    #[tokio::test(flavor = "current_thread")]
    async fn rejected_peer_never_enters_request_response_bookkeeping() {
        let mut swarm = new(Some(peer(1))).unwrap();
        let address: Multiaddr = "/ip4/127.0.0.1/udp/1/quic-v1".parse().unwrap();
        for seed in 2..66 {
            let remote = peer(seed);
            assert!(swarm
                .behaviour_mut()
                .handle_established_inbound_connection(
                    ConnectionId::new_unchecked(seed as usize),
                    remote,
                    &address,
                    &address
                )
                .is_err());
            assert!(
                !swarm.behaviour().chat.is_connected(&remote),
                "denied peer leaked into request-response state"
            );
        }
    }
    #[tokio::test(flavor = "current_thread")]
    async fn denied_second_connection_does_not_corrupt_first_connection_close() {
        let remote = peer(1);
        let mut swarm = new(Some(remote)).unwrap();
        let address: Multiaddr = "/ip4/127.0.0.1/udp/1/quic-v1".parse().unwrap();
        let endpoint = ConnectedPoint::Listener {
            local_addr: address.clone(),
            send_back_addr: address.clone(),
        };
        let first = ConnectionId::new_unchecked(1);
        let second = ConnectionId::new_unchecked(2);
        let _handler = swarm
            .behaviour_mut()
            .handle_established_inbound_connection(first, remote, &address, &address)
            .unwrap();
        swarm
            .behaviour_mut()
            .on_swarm_event(FromSwarm::ConnectionEstablished(ConnectionEstablished {
                peer_id: remote,
                connection_id: first,
                endpoint: &endpoint,
                failed_addresses: &[],
                other_established: 0,
            }));
        assert!(swarm
            .behaviour_mut()
            .handle_established_inbound_connection(second, remote, &address, &address)
            .is_err());
        swarm
            .behaviour_mut()
            .on_swarm_event(FromSwarm::ConnectionClosed(ConnectionClosed {
                peer_id: remote,
                connection_id: first,
                endpoint: &endpoint,
                cause: None,
                remaining_established: 0,
            }));
        assert!(!swarm.behaviour().chat.is_connected(&remote));
    }
}
