//! Local regression coverage for addresses sent in signed peer discovery records.

use std::collections::HashSet;

use libp2p::core::PeerRecord;
use malachitebft_metrics::Registry;

use super::*;

async fn identify_info(
    external_addrs: Vec<Multiaddr>,
) -> (identify::Info, Multiaddr, libp2p::PeerId) {
    let identity = NetworkIdentity::new("seed".into(), Keypair::generate_ed25519(), None);
    let seed_id = identity.keypair.public().to_peer_id();
    let config = Config {
        listen_addr: "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
        external_addrs,
        persistent_peers: Vec::new(),
        persistent_peers_only: false,
        discovery: DiscoveryConfig {
            enabled: false,
            ..Default::default()
        },
        idle_connection_timeout: Duration::from_secs(30),
        transport: TransportProtocol::Tcp,
        gossipsub: GossipSubConfig::default(),
        pubsub_protocol: PubSubProtocol::default(),
        channel_names: ChannelNames::default(),
        rpc_max_size: 1024 * 1024,
        pubsub_max_size: 1024 * 1024,
        enable_consensus: false,
        enable_sync: false,
        protocol_names: ProtocolNames::default(),
    };
    let registry = SharedRegistry::new(Registry::default(), None);
    let (mut events, control) = spawn(identity, config, registry).await.unwrap().split();
    let listen_addr = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Event::Listening(address) = events.recv().await.expect("seed stays running") {
                break address;
            }
        }
    })
    .await
    .expect("seed starts listening");

    let observer_key = Keypair::generate_ed25519();
    let observer_identify =
        identify::Behaviour::new(identify::Config::new_with_signed_peer_record(
            ProtocolNames::default().consensus,
            &observer_key,
        ));
    let mut observer = SwarmBuilder::with_existing_identity(observer_key)
        .with_tokio()
        .with_tcp(
            libp2p::tcp::Config::default(),
            libp2p::noise::Config::new,
            libp2p::yamux::Config::default,
        )
        .unwrap()
        .with_behaviour(|_| observer_identify)
        .unwrap()
        .build();
    observer.dial(listen_addr.clone()).unwrap();
    let info = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            tokio::select! {
                event = observer.select_next_some() => {
                    if let SwarmEvent::Behaviour(identify::Event::Received { peer_id, info, .. }) = event {
                        assert_eq!(peer_id, seed_id);
                        break info;
                    }
                }
                event = events.recv() => assert!(event.is_some(), "seed stays running"),
            }
        }
    })
    .await
    .expect("observer receives signed Identify");
    control.wait_shutdown().await.unwrap();
    (info, listen_addr, seed_id)
}

fn verified_addresses(info: &identify::Info, seed_id: libp2p::PeerId) -> HashSet<Multiaddr> {
    let record = PeerRecord::from_signed_envelope(
        info.signed_peer_record.clone().expect("signed peer record"),
    )
    .expect("peer record signature verifies");
    assert_eq!(record.peer_id(), seed_id);
    record.addresses().iter().cloned().collect()
}

#[tokio::test]
async fn external_addresses_replace_private_listeners_in_signed_identify() {
    let advertised: HashSet<Multiaddr> = [
        "/dns4/seed.example/tcp/54453".parse().unwrap(),
        "/ip6/2001:db8::1/tcp/9473".parse().unwrap(),
    ]
    .into_iter()
    .collect();
    let (info, listener, seed_id) = identify_info(advertised.iter().cloned().collect()).await;
    let identified: HashSet<_> = info.listen_addrs.iter().cloned().collect();
    assert_eq!(identified, advertised);
    assert!(!identified.contains(&listener));
    assert_eq!(verified_addresses(&info, seed_id), advertised);
}

#[tokio::test]
async fn external_addresses_empty_preserves_signed_listener_discovery() {
    let (info, listener, seed_id) = identify_info(Vec::new()).await;
    let identified: HashSet<_> = info.listen_addrs.iter().cloned().collect();
    assert!(identified.contains(&listener));
    assert_eq!(verified_addresses(&info, seed_id), identified);
}
