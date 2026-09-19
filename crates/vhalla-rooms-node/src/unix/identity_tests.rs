//! Regressions for private transport identity and public validator pins.

use super::*;

#[test]
fn transport_private_key_matches_the_public_consensus_pin() {
    let challenge = b"noise-libp2p-static-key:identity-regression";
    for seed in [0, 1, 9, 0xa5, 0xff] {
        let consensus = PrivateKey::from([seed; 32]);
        let public = consensus.public_key();
        let transport = net_keypair(&consensus);
        let transport_public = transport.public();

        assert_eq!(
            transport_public
                .clone()
                .try_into_ed25519()
                .unwrap()
                .to_bytes(),
            *public.as_bytes()
        );
        assert_eq!(
            transport_public.to_peer_id().to_base58(),
            net_peer_id(&public)
        );
        assert_eq!(
            net_keypair(&consensus.clone()).public().to_peer_id(),
            transport_public.to_peer_id(),
            "restart must preserve the transport identity"
        );

        // The two Ed25519 implementations agree on the same signer.
        let signature = transport.sign(challenge).unwrap();
        assert!(public
            .verify(
                challenge,
                &Signature::from_bytes(signature.try_into().unwrap())
            )
            .is_ok());
        assert!(transport_public.verify(challenge, &consensus.sign(challenge).to_bytes()));
    }
}

#[test]
fn public_address_cannot_recreate_the_pinned_transport_signer() {
    let consensus = PrivateKey::from([37; 32]);
    let public = consensus.public_key();
    let address = Address::from_public_key(&public).into_inner();

    // Before this fix, anyone knowing the public address could derive
    // this secret and impersonate the validator during the Noise handshake.
    let mut legacy_public_seed = [0xa5; 32];
    legacy_public_seed[..address.len()].copy_from_slice(&address);
    let attacker =
        arc_malachitebft_app::types::Keypair::ed25519_from_bytes(legacy_public_seed).unwrap();
    let honest = net_keypair(&consensus);
    let challenge = b"noise-libp2p-static-key:public-address-attacker";
    let forged = attacker.sign(challenge).unwrap();

    assert!(attacker.public().verify(challenge, &forged));
    assert_ne!(
        attacker.public().to_peer_id().to_base58(),
        net_peer_id(&public)
    );
    assert!(!honest.public().verify(challenge, &forged));
    assert!(public
        .verify(
            challenge,
            &Signature::from_bytes(forged.try_into().unwrap())
        )
        .is_err());
}

#[test]
fn public_key_bytes_cannot_recreate_the_pinned_transport_signer() {
    let consensus = PrivateKey::from([71; 32]);
    let public = consensus.public_key();
    let attacker =
        arc_malachitebft_app::types::Keypair::ed25519_from_bytes(*public.as_bytes()).unwrap();
    let challenge = b"noise-libp2p-static-key:public-key-attacker";
    let forged = attacker.sign(challenge).unwrap();

    assert!(attacker.public().verify(challenge, &forged));
    assert_ne!(
        attacker.public().to_peer_id().to_base58(),
        net_peer_id(&public)
    );
    assert!(!net_keypair(&consensus).public().verify(challenge, &forged));
}
