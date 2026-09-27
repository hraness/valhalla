//! Regression tests for TCP listeners, peer addresses and advertised endpoints.
#![cfg(unix)]

use vhalla_rooms_node::{
    advertise_endpoints, net_peer_id, service_config, try_service_config, PeerSpec, PrivateKey,
};

#[test]
fn advertised_tcp_endpoints_are_separate_from_listener_and_peer_pins() {
    let mut config = service_config("proxy", "0.0.0.0", 9473, &[], false, true);
    let endpoints = [
        "seed.example.test:54453",
        "192.0.2.1:33412",
        "[2001:db8::1]:33228",
        "seed.example.test:54453",
    ]
    .map(str::to_owned);
    advertise_endpoints(&mut config, &endpoints).unwrap();
    assert_eq!(
        config.consensus.p2p.listen_addr.to_string(),
        "/ip4/0.0.0.0/tcp/9473"
    );
    assert!(config.consensus.p2p.persistent_peers.is_empty());
    let actual: Vec<_> = config
        .consensus
        .p2p
        .external_addrs
        .iter()
        .map(ToString::to_string)
        .collect();
    assert_eq!(
        actual,
        [
            "/dns4/seed.example.test/tcp/54453",
            "/ip4/192.0.2.1/tcp/33412",
            "/ip6/2001:db8::1/tcp/33228",
        ]
    );
    advertise_endpoints(&mut config, &[]).unwrap();
    assert!(config.consensus.p2p.external_addrs.is_empty());
}

#[test]
fn invalid_advertisement_does_not_partially_replace_config() {
    let mut config = service_config("proxy", "127.0.0.1", 9473, &[], false, true);
    advertise_endpoints(&mut config, &["seed.example.test:54453".into()]).unwrap();
    let before = config.consensus.p2p.external_addrs.clone();
    for invalid in [
        "",
        "0.0.0.0:9473",
        "[::]:9473",
        "[[::]]:9473",
        "224.0.0.1:9473",
        "[ff02::1]:9473",
        "seed.example.test:0",
        "seed.example.test:65536",
        "seed.example.test",
        "user@host:12",
        "bad/host:12",
        "bad host:12",
        "-host:12",
        "host..test:12",
    ] {
        assert!(
            advertise_endpoints(&mut config, &["192.0.2.1:1234".into(), invalid.into()]).is_err(),
            "{invalid}"
        );
        assert_eq!(config.consensus.p2p.external_addrs, before);
    }
    assert!(advertise_endpoints(&mut config, &vec!["seed.example.test:12".into(); 9]).is_err());
    assert_eq!(config.consensus.p2p.external_addrs, before);
}

#[test]
fn fallible_service_config_supports_ip_listeners_and_named_pinned_peers() {
    let key = PrivateKey::from([7; 32]).public_key();
    let peers = ["192.0.2.1", "seed.example.test", "[2001:db8::1]"].map(|host| PeerSpec {
        host: host.into(),
        port: 9474,
        key: Some(key),
    });
    for (listen, expected) in [
        ("0.0.0.0", "/ip4/0.0.0.0/tcp/9473"),
        ("::1", "/ip6/::1/tcp/9473"),
        ("localhost", "/ip4/127.0.0.1/tcp/9473"),
    ] {
        let config = try_service_config("service", listen, 9473, &peers, true, false).unwrap();
        assert_eq!(config.consensus.p2p.listen_addr.to_string(), expected);
        let actual: Vec<_> = config
            .consensus
            .p2p
            .persistent_peers
            .iter()
            .map(ToString::to_string)
            .collect();
        let expected: Vec<_> = [
            "/ip4/192.0.2.1/tcp/9474",
            "/dns4/seed.example.test/tcp/9474",
            "/ip6/2001:db8::1/tcp/9474",
        ]
        .map(|address| format!("{address}/p2p/{}", net_peer_id(&key)))
        .into_iter()
        .collect();
        assert_eq!(actual, expected);
    }
    let ephemeral = service_config("service", "127.0.0.1", 0, &[], false, false);
    assert_eq!(
        ephemeral.consensus.p2p.listen_addr.to_string(),
        "/ip4/127.0.0.1/tcp/0"
    );
}

#[test]
fn fallible_service_config_rejects_malformed_networking_without_panicking() {
    for (host, port) in [
        ("", 9473),
        ("bad/host", 9473),
        ("bad host", 9473),
        ("127.0.0.1:9473", 9473),
        ("127.0.0.1", 65536),
        ("127.0.0.1", usize::MAX),
    ] {
        assert!(try_service_config("service", host, port, &[], false, false).is_err());
        let peer = PeerSpec {
            host: host.into(),
            port,
            key: None,
        };
        assert!(try_service_config("service", "127.0.0.1", 9473, &[peer], false, false).is_err());
    }
    assert!(try_service_config("service", "seed.example.test", 9473, &[], false, false).is_err());
    let zero_port_peer = PeerSpec {
        host: "127.0.0.1".into(),
        port: 0,
        key: None,
    };
    assert!(try_service_config(
        "service",
        "127.0.0.1",
        9473,
        &[zero_port_peer],
        false,
        false
    )
    .is_err());
}
