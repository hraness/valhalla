//! Authenticated candidate/hydration regression tests.
use super::*;
use alloc::vec;
use ed25519_dalek::SigningKey;
use proptest::prelude::*;
use vhalla_core::{Epoch, EventId, PeerId, RoomId, Sequence};
use vhalla_crypto::{peer_id_from_seed, sign, ReplayWindow, SessionId, VerificationContext};
use vhalla_social::{
    archive::Limits, Actor, Body, ControlAction, Facet, FacetKind, FacetedText, MentionTarget,
    Operation, Placement, References, SignedRecord, Text, UnsignedRecord,
};
use vhalla_wire::Envelope;

const REALM: RealmId = RealmId(53);
fn channel() -> ChannelScope {
    ChannelScope {
        realm: RealmId(1),
        room: RoomId(2),
        epoch: Epoch(1),
    }
}
fn key(n: u8) -> SigningKey {
    SigningKey::from_bytes(&[n; 32])
}
fn pin(n: u8) -> [u8; 32] {
    key(n).verifying_key().to_bytes()
}
fn message(body: &[u8], n: u8) -> VerifiedEnvelope {
    let context = VerificationContext {
        audience: PeerId(44),
        realm: RealmId(1),
        room: RoomId(2),
        epoch: Epoch(1),
        session: SessionId(9),
    };
    let envelope = Envelope::chat(
        peer_id_from_seed([n; 32]),
        context.realm,
        context.room,
        EventId(1),
        Sequence(1),
        body,
    )
    .unwrap();
    let signed = sign(
        envelope,
        context.audience,
        context.epoch,
        context.session,
        100,
        [n; 32],
    )
    .unwrap();
    ReplayWindow::new(context, 1)
        .unwrap()
        .verify_and_accept(signed, &key(n).verifying_key(), 10)
        .unwrap()
}
fn signed(body: Body) -> SignedRecord {
    UnsignedRecord::new(pin(11), body)
        .unwrap()
        .sign_with_key(&key(11))
        .unwrap()
        .finish()
        .unwrap()
}
fn add(archive: &mut Archive, record: &SignedRecord) {
    archive
        .ingest(
            &record.encode(),
            &mut Budget::new(1, MAX_RECORD_BYTES).unwrap(),
        )
        .unwrap();
}
fn fixture() -> (Archive, OwnerId, PostRef, Vec<SignedRecord>) {
    let genesis = signed(Body::OwnerGenesis {
        controller: pin(11),
        recovery: None,
        nonce: [11; 32],
    });
    let owner = OwnerId::from_bytes(*genesis.id().as_bytes());
    let content = FacetedText::new(
        Text::new("rust @owner #rust").unwrap(),
        vec![
            Facet {
                start: 5,
                end: 11,
                kind: FacetKind::Mention(MentionTarget::Owner(owner)),
            },
            Facet {
                start: 12,
                end: 17,
                kind: FacetKind::Tag(CanonicalTag::new("rust").unwrap()),
            },
        ],
    )
    .unwrap();
    let post = signed(Body::Social {
        actor: Actor::Owner {
            owner,
            control: genesis.id(),
        },
        realm: REALM,
        sequence: 0,
        previous: None,
        operation: Operation::PostFaceted {
            placement: Placement::Profile,
            content,
            reply: None,
            quote: None,
        },
    });
    let reference = PostRef {
        post: post.id(),
        revision: post.id(),
    };
    let seal = signed(Body::Control {
        owner,
        previous: genesis.id(),
        action: ControlAction::Seal {
            realm: REALM,
            heads: References::sorted(vec![post.id()]).unwrap(),
        },
    });
    let records = vec![genesis, post, seal];
    let mut archive = Archive::new(REALM, Limits::default()).unwrap();
    for record in &records {
        add(&mut archive, record)
    }
    (archive, owner, reference, records)
}
fn request() -> Request {
    Request::new(
        [7; 32],
        REALM,
        Query::parse("rust").unwrap(),
        Some(CanonicalTag::new("rust").unwrap()),
        vec![],
    )
    .unwrap()
}

#[test]
fn actual_signed_hydration_reapplies_query_and_never_presents_poisoned_hints() {
    let (_, owner, reference, records) = fixture();
    let request = request();
    let mut round = Round::new(request.clone(), vec![pin(1)], channel()).unwrap();
    let mut local = Archive::new(REALM, Limits::default()).unwrap();
    add(&mut local, &records[0]);
    let mut provider = Provider::new(request);
    let response = provider.next(&fixture().0, owner, 10).unwrap();
    assert_eq!(response.hints(), &[reference]);
    round
        .receive(&message(&response.encode(), 1), &mut local, 10)
        .unwrap();
    let results = round
        .candidates(
            &local,
            10,
            owner,
            &DiscoveryState::new([0; 32]),
            Filters::default(),
        )
        .unwrap();
    assert_eq!(results.references, vec![reference]);
    assert!(!results.network_complete);
    let poison = PostRef {
        post: RecordId::from_bytes([0; 32]),
        revision: RecordId::from_bytes([1; 32]),
    };
    let response = Response {
        nonce: [7; 32],
        realm: REALM,
        sequence: 1,
        hints: vec![poison],
        records: vec![vec![1, 2, 3]],
        provider_remaining: 0,
    };
    round
        .receive(&message(&response.encode(), 1), &mut local, 10)
        .unwrap();
    let result = round
        .candidates(
            &local,
            10,
            owner,
            &DiscoveryState::new([0; 32]),
            Filters::default(),
        )
        .unwrap();
    assert_eq!(result.references, vec![reference]);
    assert_eq!(result.unresolved, 1);
    assert_eq!(round.stats(pin(1)).unwrap().failures, 1);
    assert!(round
        .candidates(
            &local,
            10,
            owner,
            &DiscoveryState::new([0; 32]),
            Filters {
                tag: Some(String::from("other")),
                ..Filters::default()
            }
        )
        .unwrap()
        .references
        .is_empty());
    let _ = provider;
}

#[test]
fn invalid_inner_signature_does_not_prevent_control_and_later_valid_evidence() {
    let (_, owner, reference, records) = fixture();
    let mut bad = records[1].encode();
    let index = bad.len() - 2;
    bad[index] ^= 1;
    let response = Response {
        nonce: [7; 32],
        realm: REALM,
        sequence: 0,
        hints: vec![reference],
        records: vec![
            bad,
            records[2].encode(),
            records[0].encode(),
            records[1].encode(),
        ],
        provider_remaining: 0,
    };
    let mut round = Round::new(request(), vec![pin(1)], channel()).unwrap();
    let mut local = Archive::new(REALM, Limits::default()).unwrap();
    round
        .receive(&message(&response.encode(), 1), &mut local, 10)
        .unwrap();
    assert_eq!(local.len(), 3);
    let stats = round.stats(pin(1)).unwrap();
    assert_eq!(stats.record_attempts, 4);
    assert_eq!(stats.accepted, 3);
    assert_eq!(stats.failures, 1);
    assert_eq!(
        round
            .candidates(
                &local,
                10,
                owner,
                &DiscoveryState::new([0; 32]),
                Filters::default()
            )
            .unwrap()
            .references,
        vec![reference]
    );
}

#[test]
fn delayed_retraction_and_new_control_are_applied_before_candidate_presentation() {
    let (mut provider, owner, reference, records) = fixture();
    let mut round = Round::new(request(), vec![pin(1)], channel()).unwrap();
    let mut serving = Provider::new(request());
    let mut local = Archive::new(REALM, Limits::default()).unwrap();
    round
        .receive(
            &message(&serving.next(&provider, owner, 10).unwrap().encode(), 1),
            &mut local,
            10,
        )
        .unwrap();
    let retract = signed(Body::Social {
        actor: Actor::Owner {
            owner,
            control: records[2].id(),
        },
        realm: REALM,
        sequence: 0,
        previous: None,
        operation: Operation::Retract {
            post: reference.post,
        },
    });
    add(&mut provider, &retract);
    let seal = signed(Body::Control {
        owner,
        previous: records[2].id(),
        action: ControlAction::Seal {
            realm: REALM,
            heads: References::sorted(vec![retract.id()]).unwrap(),
        },
    });
    add(&mut provider, &seal);
    for _ in 0..4 {
        let response = serving.next(&provider, owner, 10).unwrap();
        round
            .receive(&message(&response.encode(), 1), &mut local, 10)
            .unwrap();
    }
    assert!(local.get(seal.id()).is_some());
    assert!(round
        .candidates(
            &local,
            10,
            owner,
            &DiscoveryState::new([0; 32]),
            Filters::default()
        )
        .unwrap()
        .references
        .is_empty());
}

#[test]
fn nonce_realm_capability_sequence_and_expiry_are_not_peer_selected_authority() {
    let (archive, owner, _, _) = fixture();
    let mut response = Provider::new(request()).next(&archive, owner, 10).unwrap();
    let mut round = Round::new(request(), vec![pin(1)], channel()).unwrap();
    let mut local = Archive::new(REALM, Limits::default()).unwrap();
    assert_eq!(
        round.receive(&message(&response.encode(), 2), &mut local, 10),
        Err(Error::Context)
    );
    assert_eq!(round.stats(pin(1)).unwrap().attempts, 0);
    response.nonce = [9; 32];
    assert_eq!(
        round.receive(&message(&response.encode(), 1), &mut local, 10),
        Err(Error::Context)
    );
    response.nonce = [7; 32];
    response.realm = RealmId(54);
    assert_eq!(
        round.receive(&message(&response.encode(), 1), &mut local, 10),
        Err(Error::Context)
    );
    response.realm = REALM;
    let mut raw = response.encode();
    raw[9] = 99;
    assert_eq!(
        round.receive(&message(&raw, 1), &mut local, 10),
        Err(Error::Encoding)
    );
    assert_eq!(
        round.receive(&message(&response.encode(), 1), &mut local, 101),
        Err(Error::Context)
    );
    round
        .receive(&message(&response.encode(), 1), &mut local, 10)
        .unwrap();
    assert_eq!(
        round.receive(&message(&response.encode(), 1), &mut local, 10),
        Err(Error::Context)
    );
    assert_eq!(round.stats(pin(1)).unwrap().attempts, 6);
    assert_eq!(round.stats(pin(1)).unwrap().failures, 5);
}

#[test]
fn failed_peer_budget_cannot_consume_other_peers_or_hint_reserve() {
    let mut pins = vec![pin(1), pin(2)];
    pins.sort();
    let mut round = Round::new(request(), pins.clone(), channel()).unwrap();
    assert_eq!(round.next_peer(), Some(pins[0]));
    assert_eq!(round.next_peer(), Some(pins[1]));
    for _ in 0..MAX_ATTEMPTS {
        round.failed(pin(1)).unwrap();
    }
    assert_eq!(round.failed(pin(1)), Err(Error::Budget));
    assert_eq!(round.next_peer(), Some(pin(2)));
    assert_eq!(round.stats(pin(2)).unwrap(), PeerStats::default());
    let (archive, owner, reference, _) = fixture();
    let response = Provider::new(request()).next(&archive, owner, 10).unwrap();
    let mut local = Archive::new(REALM, Limits::default()).unwrap();
    round
        .receive(&message(&response.encode(), 2), &mut local, 10)
        .unwrap();
    assert_eq!(
        round
            .candidates(
                &local,
                10,
                owner,
                &DiscoveryState::new([0; 32]),
                Filters::default()
            )
            .unwrap()
            .references,
        vec![reference]
    );
}

#[test]
fn canonical_request_response_bounds_fit_actual_signed_transport() {
    assert_eq!(vhalla_crypto::MAX_SIGNED_BODY_BYTES, 65_341);
    let request = request();
    assert_eq!(
        wire::decode_request(&request.encode()).unwrap().encode(),
        request.encode()
    );
    let verified = message(&request.encode(), 1);
    assert_eq!(
        Request::from_message(&verified, pin(1), channel(), 10)
            .unwrap()
            .encode(),
        request.encode()
    );
    assert!(Request::from_message(&verified, pin(2), channel(), 10).is_err());
    let (archive, owner, _, _) = fixture();
    let response = Provider::new(request).next(&archive, owner, 10).unwrap();
    assert_eq!(
        wire::decode_response(&response.encode()).unwrap().encode(),
        response.encode()
    );
    for end in 0..response.encode().len() {
        assert!(wire::decode_response(&response.encode()[..end]).is_err());
    }
    let mut trailing = response.encode();
    trailing.push(0);
    assert!(wire::decode_response(&trailing).is_err());
}

#[test]
fn authenticated_outer_channel_is_independently_pinned() {
    let (archive, owner, _, _) = fixture();
    let response = Provider::new(request()).next(&archive, owner, 10).unwrap();
    for wrong in [
        ChannelScope {
            realm: RealmId(9),
            ..channel()
        },
        ChannelScope {
            room: RoomId(9),
            ..channel()
        },
        ChannelScope {
            epoch: Epoch(9),
            ..channel()
        },
    ] {
        let verified_request = message(&request().encode(), 1);
        assert!(matches!(
            Request::from_message(&verified_request, pin(1), wrong, 10),
            Err(Error::Context)
        ));
        let mut round = Round::new(request(), vec![pin(1)], wrong).unwrap();
        let mut local = Archive::new(REALM, Limits::default()).unwrap();
        assert_eq!(
            round.receive(&message(&response.encode(), 1), &mut local, 10),
            Err(Error::Context)
        );
        assert!(local.is_empty());
        assert_eq!(round.stats(pin(1)).unwrap().failures, 1);
    }
}

#[test]
fn rejected_oversized_authenticated_bytes_are_charged() {
    let raw = vec![0; MAX_FRAME + 1];
    let verified = message(&raw, 1);
    let mut round = Round::new(request(), vec![pin(1)], channel()).unwrap();
    let mut local = Archive::new(REALM, Limits::default()).unwrap();
    assert_eq!(round.receive(&verified, &mut local, 10), Err(Error::Bounds));
    let stats = round.stats(pin(1)).unwrap();
    assert_eq!(stats.bytes, raw.len());
    assert_eq!(stats.attempts, 1);
    assert_eq!(stats.failures, 1);
    assert!(local.is_empty());
}

#[test]
fn zero_hint_and_zero_hit_queries_preserve_incomplete_history() {
    let (_, owner, _, records) = fixture();
    let mut local = Archive::new(REALM, Limits::default()).unwrap();
    add(&mut local, &records[0]);
    // Retain the signed sealing control while its explicitly named post is missing.
    add(&mut local, &records[2]);
    let round = Round::new(request(), vec![pin(1)], channel()).unwrap();
    let result = round
        .candidates(
            &local,
            10,
            owner,
            &DiscoveryState::new([0; 32]),
            Filters::default(),
        )
        .unwrap();
    assert!(result.references.is_empty());
    assert!(!result.local_query_complete);
    assert!(!result.network_complete);
}

#[test]
fn served_pages_converge_to_zero_remaining_without_resending() {
    // Seven owner genesis records exceed one five-record page; each page must
    // grow the effective peer inventory so the round terminates instead of
    // rotating back over already-served records.
    let mut archive = Archive::new(REALM, Limits::default()).unwrap();
    let mut owner = None;
    for n in 0..7u8 {
        let genesis = signed(Body::OwnerGenesis {
            controller: pin(11),
            recovery: None,
            nonce: [n + 50; 32],
        });
        if n == 0 {
            owner = Some(OwnerId::from_bytes(*genesis.id().as_bytes()));
        }
        add(&mut archive, &genesis);
    }
    let owner = owner.unwrap();
    let request = Request::new([7; 32], REALM, Query::parse("x").unwrap(), None, vec![]).unwrap();
    let mut provider = Provider::new(request);
    let mut emitted = std::collections::BTreeSet::new();
    let mut pages = 0;
    loop {
        let page = provider.next(&archive, owner, 10).unwrap();
        for raw in &page.records {
            let id = SignedRecord::decode(raw).unwrap().id();
            assert!(emitted.insert(id), "record resent across pages");
        }
        pages += 1;
        if page.provider_remaining() == 0 {
            break;
        }
        assert!(pages < MAX_ATTEMPTS, "remaining never converged");
    }
    assert_eq!(pages, 2);
    assert_eq!(emitted.len(), 7);
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]
    #[test]
    fn untrusted_frame_decoders_terminate_and_canonicalize_nothing(raw in prop::collection::vec(any::<u8>(),0..2000)) {
        if let Ok(request)=wire::decode_request(&raw) {prop_assert_eq!(request.encode(),raw.clone());}
        if let Ok(response)=wire::decode_response(&raw) {prop_assert_eq!(response.encode(),raw);}
    }
    #[test]
    fn arbitrary_failed_attempts_never_gain_credit(failures in 0usize..80) {
        let mut round=Round::new(request(),vec![pin(1)],channel()).unwrap();for _ in 0..failures {let _=round.failed(pin(1));}prop_assert_eq!(round.stats(pin(1)).unwrap().attempts,failures.min(MAX_ATTEMPTS));prop_assert_eq!(round.stats(pin(1)).unwrap().failures,failures.min(MAX_ATTEMPTS));
    }
}
