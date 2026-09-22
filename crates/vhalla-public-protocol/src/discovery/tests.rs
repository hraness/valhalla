use super::*;
use crate::{AdvertisementClaims, Capabilities, Endpoint, UnsignedAdvertisement, PROTOCOL_VERSION};
use alloc::vec;

fn advertisement(key: &SigningKey, sequence: u64, now: u64) -> PeerAdvertisement {
    UnsignedAdvertisement::new(AdvertisementClaims {
        network: [4; 32],
        application_key: key.verifying_key().to_bytes(),
        sequence,
        issued_at: now,
        expires_at: now + 3600,
        protocol: PROTOCOL_VERSION,
        capabilities: Capabilities::READ,
        endpoints: vec![Endpoint::parse("https://candidate.vhalla.dev:443/vhalla/v1").unwrap()],
    })
    .unwrap()
    .sign_with_key(key)
    .unwrap()
}
fn challenge(
    ad: &PeerAdvertisement,
    known: bool,
) -> (SigningKey, DiscoveryRequest, RegistrationChallenge) {
    let receiver = SigningKey::from_bytes(&[8; 32]);
    let req = DiscoveryRequest::new(
        [7; 32],
        DiscoveryKind::Challenge {
            publisher: ad.unverified_claims().application_key,
            advertisement: hash(&ad.encode()),
        },
    )
    .unwrap();
    let c = UnsignedRegistrationChallenge::new(
        [4; 32],
        receiver.verifying_key().to_bytes(),
        req,
        1000,
        known,
    )
    .unwrap()
    .sign_with_key(&receiver)
    .unwrap();
    (receiver, req, c)
}
#[test]
fn discovery_requests_pages_and_proofs_are_canonical_and_bound() {
    let signer = SigningKey::from_bytes(&[8; 32]);
    let a = advertisement(&SigningKey::from_bytes(&[1; 32]), 1, 1000);
    let b = advertisement(&SigningKey::from_bytes(&[2; 32]), 1, 1000);
    let mut ads = vec![a, b];
    ads.sort_by_key(|a| a.unverified_claims().application_key);
    let req = DiscoveryRequest::new(
        [7; 32],
        DiscoveryKind::List {
            generation: 0,
            after: [0; 32],
            count: 2,
        },
    )
    .unwrap();
    assert_eq!(DiscoveryRequest::parse_target(&req.target()).unwrap(), req);
    assert!(DiscoveryRequest::parse_target(&req.target().replace("count=2", "count=02")).is_err());
    assert!(DiscoveryRequest::new(
        [7; 32],
        DiscoveryKind::List {
            generation: 0,
            after: [1; 32],
            count: 2
        }
    )
    .is_err());
    let page = PeerPage::new([4; 32], 3, [0; 32], false, ads.clone()).unwrap();
    let body = page.encode();
    let decoded = PeerPage::decode(&body).unwrap();
    assert_eq!(decoded, page);
    decoded.check_request([4; 32], req).unwrap();
    ads.reverse();
    assert!(PeerPage::new([4; 32], 3, [0; 32], false, ads).is_err());
    let proof =
        UnsignedDiscoveryResponse::new([4; 32], signer.verifying_key().to_bytes(), req, &body)
            .unwrap()
            .sign_with_key(&signer)
            .unwrap();
    let proof = DiscoveryResponseProof::decode(&proof.encode()).unwrap();
    proof
        .verify([4; 32], signer.verifying_key().to_bytes(), req, &body)
        .unwrap();
    assert!(proof
        .verify([5; 32], signer.verifying_key().to_bytes(), req, &body)
        .is_err());
    let mut tampered = body.clone();
    tampered[5] ^= 1;
    assert!(proof
        .verify([4; 32], signer.verifying_key().to_bytes(), req, &tampered)
        .is_err());
    let wrong = DiscoveryRequest::new([6; 32], req.kind()).unwrap();
    assert!(proof
        .verify([4; 32], signer.verifying_key().to_bytes(), wrong, &body)
        .is_err());
    let mut trailing = body;
    trailing.push(0);
    assert!(PeerPage::decode(&trailing).is_err());
}
#[test]
fn discovery_hashcash_requires_exact_network_peer_ad_time_and_subject() {
    let publisher = SigningKey::from_bytes(&[3; 32]);
    let ad = advertisement(&publisher, 1, 1000);
    let (receiver, request, challenge) = challenge(&ad, false);
    let peer = receiver.verifying_key().to_bytes();
    let raw = challenge.encode();
    assert_eq!(raw.len(), REGISTRATION_CHALLENGE_BYTES);
    let challenge = RegistrationChallenge::decode(&raw).unwrap();
    assert!(challenge.verify([5; 32], peer, request, 1000).is_err());
    assert!(challenge.verify([4; 32], [2; 32], request, 1000).is_err());
    assert!(challenge.verify([4; 32], peer, request, 1060).is_err());
    assert!(challenge.verify([4; 32], peer, request, 999).is_err());
    let verified = challenge.verify([4; 32], peer, request, 1000).unwrap();
    assert_eq!(verified.difficulty(), 20);
    assert_eq!(verified.solve(0), Err(DiscoveryError::Bounds));
    assert_eq!(
        verified.solve(MAX_SOLVE_ATTEMPTS + 1),
        Err(DiscoveryError::Bounds)
    );
    assert!(verified.solve_range(u64::MAX, 2).is_err());
    let nonce = verified.solve(MAX_SOLVE_ATTEMPTS).unwrap();
    assert_eq!(verified.solve_range(nonce, 1).unwrap(), Some(nonce));
    let reg = UnsignedRegistration::new(ad.clone(), verified, nonce)
        .unwrap()
        .sign_with_key(&publisher)
        .unwrap();
    let raw = reg.encode();
    assert!(raw.len() <= MAX_REGISTRATION_BYTES);
    let decoded = Registration::decode(&raw).unwrap();
    decoded.verify([4; 32], peer, 1000, false).unwrap();
    let request = DiscoveryRequest::new(
        [9; 32],
        DiscoveryKind::Register {
            registration: hash(&raw),
        },
    )
    .unwrap();
    request.check_body(&raw).unwrap();
    let mut tamper = raw.clone();
    *tamper.last_mut().unwrap() ^= 1;
    assert!(request.check_body(&tamper).is_err());
    assert!(Registration::decode(&tamper)
        .unwrap()
        .verify([4; 32], peer, 1000, false)
        .is_err());
    let mut changed = decoded;
    changed.advertisement = advertisement(&publisher, 2, 1000);
    assert!(changed.verify([4; 32], peer, 1000, false).is_err());
    let (_receiver, request, cheap) = self::challenge(&ad, true);
    let cheap = cheap.verify([4; 32], peer, request, 1000).unwrap();
    let nonce = cheap.solve(1000).unwrap();
    let cheap = UnsignedRegistration::new(ad, cheap, nonce)
        .unwrap()
        .sign_with_key(&publisher)
        .unwrap();
    cheap.verify([4; 32], peer, 1000, true).unwrap();
    assert_eq!(
        cheap.verify([4; 32], peer, 1000, false),
        Err(DiscoveryError::Work)
    );
}
#[test]
fn discovery_decoder_limits_and_weak_subject_are_rejected() {
    assert!(PeerPage::decode(&vec![0; MAX_PEER_PAGE_BYTES + 1]).is_err());
    assert!(Registration::decode(&vec![0; MAX_REGISTRATION_BYTES + 1]).is_err());
    let mut weak = [0; 32];
    weak[0] = 1;
    assert!(DiscoveryRequest::new(
        [1; 32],
        DiscoveryKind::Challenge {
            publisher: weak,
            advertisement: [3; 32]
        }
    )
    .is_err());
    let publisher = SigningKey::from_bytes(&[3; 32]);
    let ad = advertisement(&publisher, 1, 1000);
    let (_, _, challenge) = self::challenge(&ad, true);
    let mut raw = challenge.encode();
    raw.push(0);
    assert!(RegistrationChallenge::decode(&raw).is_err());
    let r = RegistrationReceipt::new(
        [4; 32],
        SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes(),
        publisher.verifying_key().to_bytes(),
        1,
        2,
        2000,
        90000,
    )
    .unwrap();
    assert_eq!(RegistrationReceipt::decode(&r.encode()).unwrap(), r);
}

#[test]
fn discovery_future_issue_skew_boundary_and_receipt_scope_are_exact() {
    let publisher = SigningKey::from_bytes(&[3; 32]);
    for (issued, accepted) in [(1300, true), (1301, false)] {
        let ad = advertisement(&publisher, 1, issued);
        let (receiver, request, challenge) = challenge(&ad, true);
        let receiver = receiver.verifying_key().to_bytes();
        let challenge = challenge.verify([4; 32], receiver, request, 1000).unwrap();
        let nonce = challenge.solve(1000).unwrap();
        let registration = UnsignedRegistration::new(ad.clone(), challenge, nonce)
            .unwrap()
            .sign_with_key(&publisher)
            .unwrap();
        assert_eq!(
            registration.verify([4; 32], receiver, 1000, true).is_ok(),
            accepted
        );
        assert!(registration.verify([4; 32], receiver, 1000, false).is_err());
        let receipt = RegistrationReceipt::new(
            [4; 32],
            receiver,
            publisher.verifying_key().to_bytes(),
            1,
            2,
            issued + 3600,
            90000,
        )
        .unwrap();
        receipt.check([4; 32], receiver, &ad).unwrap();
        assert!(receipt.check([5; 32], receiver, &ad).is_err());
        assert!(receipt.check([4; 32], [9; 32], &ad).is_err());
        assert!(receipt
            .check([4; 32], receiver, &advertisement(&publisher, 2, issued))
            .is_err());
    }
}
