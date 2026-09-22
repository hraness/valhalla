use super::*;
use alloc::{format, string::ToString, vec};

fn key() -> SigningKey {
    SigningKey::from_bytes(&[7; 32])
}

fn claims() -> AdvertisementClaims {
    AdvertisementClaims {
        network: [3; 32],
        application_key: key().verifying_key().to_bytes(),
        sequence: 1,
        issued_at: 1_000,
        expires_at: 1_100,
        protocol: PROTOCOL_VERSION,
        capabilities: Capabilities::from_bits(7).unwrap(),
        endpoints: vec![
            Endpoint::parse("https://peer.valhalla.net:443/vhalla/v1").unwrap(),
            Endpoint::parse("wss://peer.valhalla.net:443/vhalla/v1").unwrap(),
        ],
    }
}

fn signed(claims: AdvertisementClaims) -> PeerAdvertisement {
    UnsignedAdvertisement::new(claims)
        .unwrap()
        .sign_with_key(&key())
        .unwrap()
}

fn policy() -> VerificationPolicy {
    VerificationPolicy {
        network: [3; 32],
        now: 1_010,
        max_clock_skew_seconds: 30,
        max_ttl_seconds: 300,
    }
}

#[test]
fn canonical_signed_round_trip_and_external_signature_agree() {
    let proposed = claims();
    let unsigned = UnsignedAdvertisement::new(proposed.clone()).unwrap();
    let external = key().sign(&unsigned.signing_bytes()).to_bytes();
    let advertisement = unsigned.clone().attach_signature(external).unwrap();
    assert_eq!(advertisement, unsigned.sign_with_key(&key()).unwrap());
    let raw = advertisement.encode();
    assert!(raw.len() <= MAX_ADVERTISEMENT_BYTES);
    let decoded = PeerAdvertisement::decode(&raw).unwrap();
    assert_eq!(decoded.encode(), raw);
    let verified = decoded.verify(&policy(), None).unwrap();
    assert_eq!(verified.claims(), &proposed);
    assert_eq!(verified.verified_at(), policy().now);
    assert_eq!(verified.encode(), raw);
    assert!(verified.claims().capabilities.contains(Capabilities::READ));
}

#[test]
fn every_single_bit_change_to_signed_frame_is_rejected() {
    let raw = signed(claims()).encode();
    for index in 0..raw.len() {
        for bit in 0..8 {
            let mut changed = raw.clone();
            changed[index] ^= 1 << bit;
            assert!(
                PeerAdvertisement::decode(&changed)
                    .and_then(|ad| ad.verify(&policy(), None))
                    .is_err(),
                "accepted changed byte {index}, bit {bit}"
            );
        }
    }
}

#[test]
fn every_truncation_and_trailing_data_fail_closed() {
    let raw = signed(claims()).encode();
    for end in 0..raw.len() {
        assert!(
            PeerAdvertisement::decode(&raw[..end]).is_err(),
            "prefix {end}"
        );
    }
    let mut trailing = raw;
    trailing.push(0);
    assert_eq!(PeerAdvertisement::decode(&trailing), Err(Error::Encoding));
    assert_eq!(
        PeerAdvertisement::decode(&vec![0; MAX_ADVERTISEMENT_BYTES + 1]),
        Err(Error::Bounds)
    );
}

#[test]
fn wrong_network_expiry_and_future_clock_have_distinct_failures() {
    let advertisement = signed(claims());
    let mut p = policy();
    p.network = [4; 32];
    assert_eq!(advertisement.verify(&p, None), Err(Error::Network));
    p = policy();
    p.now = 1_100;
    assert_eq!(advertisement.verify(&p, None), Err(Error::Expired));
    p.now = 1_099;
    assert!(advertisement.verify(&p, None).is_ok());
    p.now = 969;
    assert_eq!(advertisement.verify(&p, None), Err(Error::IssuedInFuture));
    p.now = 970;
    assert!(advertisement.verify(&p, None).is_ok());
    p.now = u64::MAX;
    assert_eq!(advertisement.verify(&p, None), Err(Error::Expired));
}

#[test]
fn lifetime_and_policy_limits_do_not_wrap() {
    let advertisement = signed(claims());
    let mut p = policy();
    p.max_ttl_seconds = 99;
    assert_eq!(advertisement.verify(&p, None), Err(Error::Lifetime));
    for ttl in [0, MAX_TTL_SECONDS + 1, u64::MAX] {
        p = policy();
        p.max_ttl_seconds = ttl;
        assert_eq!(advertisement.verify(&p, None), Err(Error::Policy));
    }
    p = policy();
    p.max_clock_skew_seconds = MAX_CLOCK_SKEW_SECONDS + 1;
    assert_eq!(advertisement.verify(&p, None), Err(Error::Policy));
    p = policy();
    p.network = [0; 32];
    assert_eq!(advertisement.verify(&p, None), Err(Error::Policy));
    for expiry in [0, 999, 1_000, 1_000 + MAX_TTL_SECONDS + 1, u64::MAX] {
        let mut c = claims();
        c.expires_at = expiry;
        assert_eq!(UnsignedAdvertisement::new(c), Err(Error::Lifetime));
    }
    let mut c = claims();
    c.issued_at = u64::MAX - 100;
    c.expires_at = u64::MAX;
    p = policy();
    p.now = u64::MAX - 110;
    assert!(signed(c).verify(&p, None).is_ok());
}

#[test]
fn signatures_cannot_cross_domains_or_keys() {
    let unsigned = UnsignedAdvertisement::new(claims()).unwrap();
    let other = SigningKey::from_bytes(&[8; 32]);
    assert_eq!(unsigned.clone().sign_with_key(&other), Err(Error::Signer));
    let wrong_key = other.sign(&unsigned.signing_bytes()).to_bytes();
    assert_eq!(
        unsigned.clone().attach_signature(wrong_key),
        Err(Error::Signature)
    );
    // An Ed25519 signature over the same raw fields without the protocol
    // domain must not be accepted as an advertisement.
    let no_domain = key().sign(&unsigned_bytes(&claims())).to_bytes();
    assert_eq!(unsigned.attach_signature(no_domain), Err(Error::Signature));
}

#[test]
fn weak_keys_and_zero_scope_never_become_verified_evidence() {
    let mut identity = [0; 32];
    identity[0] = 1;
    for weak in [[0; 32], identity] {
        let mut c = claims();
        c.application_key = weak;
        assert_eq!(UnsignedAdvertisement::new(c), Err(Error::Key));
        let mut raw = signed(claims()).encode();
        raw[37..69].copy_from_slice(&weak);
        assert_eq!(PeerAdvertisement::decode(&raw), Err(Error::Key));
    }
    let mut c = claims();
    c.network = [0; 32];
    assert_eq!(UnsignedAdvertisement::new(c), Err(Error::Network));
}

#[test]
fn monotone_sequence_is_scoped_and_survives_previous_expiration() {
    let first = signed(claims()).verify(&policy(), None).unwrap();
    assert_eq!(
        signed(claims()).verify(&policy(), Some(&first.sequence_anchor())),
        Err(Error::Sequence)
    );
    let mut c = claims();
    c.issued_at = 1_200;
    c.expires_at = 1_300;
    let mut p = policy();
    p.now = 1_210;
    // A freshly re-signed old sequence cannot replace expired retained evidence.
    assert_eq!(
        signed(c.clone()).verify(&p, Some(&first.sequence_anchor())),
        Err(Error::Sequence)
    );
    c.sequence = 2;
    assert!(signed(c.clone())
        .verify(&p, Some(&first.sequence_anchor()))
        .is_ok());
    c.network = [4; 32];
    p.network = c.network;
    assert_eq!(
        signed(c).verify(&p, Some(&first.sequence_anchor())),
        Err(Error::Network)
    );

    let other = SigningKey::from_bytes(&[8; 32]);
    let mut c = claims();
    c.application_key = other.verifying_key().to_bytes();
    let peer = UnsignedAdvertisement::new(c)
        .unwrap()
        .sign_with_key(&other)
        .unwrap();
    assert_eq!(
        peer.verify(&policy(), Some(&first.sequence_anchor())),
        Err(Error::Peer)
    );

    let mut c = claims();
    c.sequence = 0;
    assert_eq!(UnsignedAdvertisement::new(c), Err(Error::Sequence));
    let mut c = claims();
    c.sequence = u64::MAX;
    let terminal = signed(c.clone())
        .verify(&policy(), Some(&first.sequence_anchor()))
        .unwrap();
    assert_eq!(
        signed(c).verify(&policy(), Some(&terminal.sequence_anchor())),
        Err(Error::Sequence)
    );
}

#[test]
fn unknown_protocol_capabilities_and_excess_routes_fail_closed() {
    for bits in [0, 8, u32::MAX] {
        assert_eq!(Capabilities::from_bits(bits), Err(Error::Protocol));
    }
    let mut c = claims();
    c.protocol = 2;
    assert_eq!(UnsignedAdvertisement::new(c), Err(Error::Protocol));
    let mut c = claims();
    c.endpoints.clear();
    assert_eq!(UnsignedAdvertisement::new(c), Err(Error::Bounds));
    let mut c = claims();
    c.endpoints = vec![c.endpoints[0].clone(); MAX_ENDPOINTS + 1];
    assert_eq!(UnsignedAdvertisement::new(c), Err(Error::Bounds));

    let raw = signed(claims()).encode();
    for (offset, value, expected) in [
        (4, 2, Error::Protocol),
        (94, 2, Error::Protocol),
        (98, 8, Error::Protocol),
        (99, 0, Error::Bounds),
        (99, 5, Error::Bounds),
        (100, 255, Error::Bounds),
    ] {
        let mut bad = raw.clone();
        bad[offset] = value;
        assert_eq!(PeerAdvertisement::decode(&bad), Err(expected));
    }
}

#[test]
fn duplicate_and_unsorted_endpoints_are_not_normalized() {
    let mut c = claims();
    c.endpoints.reverse();
    assert_eq!(UnsignedAdvertisement::new(c), Err(Error::EndpointOrder));
    let mut c = claims();
    c.endpoints[1] = c.endpoints[0].clone();
    assert_eq!(UnsignedAdvertisement::new(c), Err(Error::EndpointOrder));
    // A foreign signature does not let the decoder bypass canonical ordering.
    let mut c = claims();
    c.endpoints.reverse();
    let mut raw = unsigned_bytes(&c);
    raw.extend_from_slice(&[0; 64]);
    assert_eq!(PeerAdvertisement::decode(&raw), Err(Error::EndpointOrder));
}

#[test]
fn public_literal_routes_and_dns_are_typed_without_dialing() {
    for url in [
        "https://8.8.8.8:443/vhalla/v1",
        "wss://1.1.1.1:8443/vhalla/v1",
        "https://[2606:4700:4700::1111]:443/vhalla/v1",
        "wss://node-2.valhalla.net:65535/vhalla/v1",
    ] {
        let endpoint = Endpoint::parse(url).unwrap();
        assert_eq!(endpoint.as_str(), url);
        assert_ne!(endpoint.port(), 0);
    }
    let endpoint = Endpoint::parse("https://8.8.8.8:443/vhalla/v1").unwrap();
    assert_eq!(endpoint.scheme(), Scheme::Https);
    assert!(matches!(endpoint.host(), Host::Ip(_)));
    let endpoint = Endpoint::parse("wss://peer.valhalla.net:443/vhalla/v1").unwrap();
    assert_eq!(endpoint.scheme(), Scheme::Wss);
    assert!(matches!(endpoint.host(), Host::Dns(_)));
}

#[test]
fn private_reserved_transition_and_noncanonical_ip_routes_are_rejected() {
    for host in [
        "0.0.0.0",
        "10.1.2.3",
        "100.64.0.1",
        "100.127.255.255",
        "127.0.0.1",
        "169.254.169.254",
        "172.16.0.1",
        "172.31.255.255",
        "192.0.0.9",
        "192.0.2.1",
        "192.88.99.1",
        "192.168.0.1",
        "198.18.0.1",
        "198.19.255.255",
        "198.51.100.1",
        "203.0.113.1",
        "224.0.0.1",
        "240.0.0.1",
        "255.255.255.255",
        "127.1",
        "2130706433",
        "0x7f000001",
        "0x7f.0.0.1",
        "0177.0.0.1",
        "8.08.8.8",
        "[::]",
        "[::1]",
        "[::ffff:8.8.8.8]",
        "[64:ff9b::808:808]",
        "[100::1]",
        "[2001::1]",
        "[2001:1::1]",
        "[2001:db8::1]",
        "[2002:808:808::1]",
        "[3fff::1]",
        "[3fff:fff::1]",
        "[5f00::1]",
        "[fc00::1]",
        "[fe80::1]",
        "[ff02::1]",
        "[fe80::1%25en0]",
        "[2606:4700:4700:0:0:0:0:1111]",
        "[2606:4700:4700::ABCD]",
        "2606:4700:4700::1111",
    ] {
        assert!(
            Endpoint::parse(&format!("https://{host}:443/vhalla/v1")).is_err(),
            "accepted {host}"
        );
    }
}

#[test]
fn endpoint_syntax_is_canonical_and_has_no_ambient_url_authority() {
    for url in [
        "http://peer.valhalla.net:443/vhalla/v1",
        "ws://peer.valhalla.net:443/vhalla/v1",
        "HTTPS://peer.valhalla.net:443/vhalla/v1",
        "https://PEER.valhalla.net:443/vhalla/v1",
        "https://peer.valhalla.net:0/vhalla/v1",
        "https://peer.valhalla.net:0443/vhalla/v1",
        "https://peer.valhalla.net:+443/vhalla/v1",
        "https://peer.valhalla.net:65536/vhalla/v1",
        "https://peer.valhalla.net/vhalla/v1",
        "https://peer.valhalla.net:443/vhalla/v1/",
        "https://peer.valhalla.net:443/other",
        "https://peer.valhalla.net:443/vhalla/v1?token=x",
        "https://peer.valhalla.net:443/vhalla/v1#x",
        "https://user:password@peer.valhalla.net:443/vhalla/v1",
        "https://peer.valhalla.net.:443/vhalla/v1",
        "https://peer..valhalla.net:443/vhalla/v1",
        "https://-peer.valhalla.net:443/vhalla/v1",
        "https://peer_.valhalla.net:443/vhalla/v1",
        "https://peer.valhalla.net%2f:443/vhalla/v1",
        "https://peer.valhalla.net\\@127.0.0.1:443/vhalla/v1",
        "https://localhost:443/vhalla/v1",
        "https://peer.localhost:443/vhalla/v1",
        "https://peer.local:443/vhalla/v1",
        "https://peer.home.arpa:443/vhalla/v1",
        "https://peer.example.com:443/vhalla/v1",
        "https://peer.test:443/vhalla/v1",
        "https://peer.onion:443/vhalla/v1",
        "https://péér.valhalla.net:443/vhalla/v1",
        "https://peer.valhalla.net:443\n/vhalla/v1",
    ] {
        assert!(Endpoint::parse(url).is_err(), "accepted {url}");
    }
    let too_long = "x".repeat(MAX_ENDPOINT_BYTES + 1);
    assert_eq!(Endpoint::parse(&too_long), Err(Error::Bounds));
}

#[test]
fn maximum_dns_names_and_endpoint_count_round_trip_within_wire_bound() {
    let mut c = claims();
    c.endpoints.clear();
    for prefix in ['a', 'b', 'c', 'd'] {
        let host = format!(
            "{prefix}{}.{}.{}.{}",
            "a".repeat(62),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61)
        );
        assert_eq!(host.len(), 253);
        c.endpoints
            .push(Endpoint::parse(&format!("https://{host}:65535/vhalla/v1")).unwrap());
    }
    let advertisement = signed(c);
    let raw = advertisement.encode();
    assert_eq!(raw.len(), FIXED_BYTES + MAX_ENDPOINTS * (2 + 277));
    assert!(raw.len() <= MAX_ADVERTISEMENT_BYTES);
    assert!(PeerAdvertisement::decode(&raw)
        .unwrap()
        .verify(&policy(), None)
        .is_ok());
    let long_label = format!("https://{}.net:443/vhalla/v1", "a".repeat(64));
    assert_eq!(Endpoint::parse(&long_label), Err(Error::Endpoint));
}

#[test]
fn decoded_claims_cannot_mutate_the_verified_original() {
    let advertisement = signed(claims());
    let verified = advertisement.verify(&policy(), None).unwrap();
    let original = verified.encode();
    let mut detached = verified.claims().clone();
    detached.endpoints.clear();
    detached.network = [9; 32];
    assert_eq!(verified.encode(), original);
    assert_eq!(verified.claims().network, policy().network);
    assert_eq!(advertisement.unverified_claims(), verified.claims());
    assert_eq!(API_BASE.to_string(), "/vhalla/v1");
}

#[test]
fn expired_persisted_signature_restores_only_scoped_sequence_floor() {
    let first = signed(claims()).verify(&policy(), None).unwrap();
    let bytes = first.encode();
    let reopened = PeerAdvertisement::decode(&bytes).unwrap();
    let mut p = policy();
    p.now = 1_210;
    assert_eq!(reopened.verify(&p, None), Err(Error::Expired));
    let anchor = reopened.restore_sequence_anchor(p.network).unwrap();
    assert_eq!(anchor, first.sequence_anchor());
    assert_eq!(anchor.network(), &p.network);
    assert_eq!(anchor.application_key(), &key().verifying_key().to_bytes());
    assert_eq!(anchor.sequence(), 1);
    let mut next = claims();
    next.issued_at = 1_200;
    next.expires_at = 1_300;
    assert_eq!(
        signed(next.clone()).verify(&p, Some(&anchor)),
        Err(Error::Sequence)
    );
    next.sequence = 2;
    assert!(signed(next).verify(&p, Some(&anchor)).is_ok());
    assert_eq!(
        reopened.restore_sequence_anchor([4; 32]),
        Err(Error::Network)
    );
    let mut bad = bytes;
    let last = bad.len() - 1;
    bad[last] ^= 1;
    assert_eq!(
        PeerAdvertisement::decode(&bad)
            .unwrap()
            .restore_sequence_anchor(p.network),
        Err(Error::Signature)
    );
}
