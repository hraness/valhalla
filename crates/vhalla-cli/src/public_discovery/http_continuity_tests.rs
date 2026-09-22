use super::*;
use vhalla_public_protocol::continuity as wire;
use vhalla_room_activity::{
    Content, EventClaims, EventId, RoomScope, Text, UnsignedEvent, VerifiedEvent,
};

fn frames(count: usize, full: bool) -> Vec<VerifiedEvent> {
    let key = ed25519_dalek::SigningKey::from_bytes(&[42; 32]);
    let mut previous = EventId::ZERO;
    (1..=count)
        .map(|sequence| {
            let event = UnsignedEvent::new(EventClaims {
                scope: RoomScope {
                    network: [7; 32],
                    realm: vhalla_core::RealmId(77),
                    directory: vhalla_rooms::DirectoryId::from_bytes([5; 32]),
                    room: vhalla_rooms::RoomGenesisId::from_bytes([8; 32]),
                },
                policy: vhalla_rooms::RoomRecordId::from_bytes([9; 32]),
                author: key.verifying_key().to_bytes(),
                sequence: sequence as u64,
                previous,
                created_at: 1234,
                content: Content::Text(
                    Text::new(&if full {
                        "x".repeat(vhalla_room_activity::MAX_TEXT_BYTES)
                    } else {
                        "fixture".into()
                    })
                    .unwrap(),
                ),
            })
            .unwrap()
            .sign_with_key(&key)
            .unwrap()
            .verify()
            .unwrap();
            previous = event.id();
            event
        })
        .collect()
}
fn context(event: &VerifiedEvent) -> wire::RequestContext {
    wire::RequestContext {
        scope: event.claims().scope.into(),
        nonce: [1; 32],
        operation: [2; 16],
        floor: wire::Observed {
            height: 3,
            frontier: [4; 32],
        },
    }
}

#[test]
fn continuity_http_exact_typed_roles_reach_cancellation_without_dial_or_discovery_widening() {
    let events = frames(33, false);
    let context = context(&events[0]);
    let author = events[0].claims().author;
    let stage = wire::Body::stage(events[..32].to_vec()).unwrap();
    let commit = wire::Body::commit(events[..32].to_vec(), events[32].clone()).unwrap();
    let stage_request =
        wire::Request::stage(context, author, wire::Position::EMPTY, None, &stage).unwrap();
    let commit_request =
        wire::Request::commit(context, author, wire::Position::EMPTY, None, &commit).unwrap();
    let status = wire::Request::new(
        context,
        wire::Selection::Author(author),
        wire::Kind::Status {
            minimum: wire::Position::EMPTY,
        },
    )
    .unwrap();
    let evidence = wire::Request::new(
        context,
        wire::Selection::Author(author),
        wire::Kind::Evidence {
            after: wire::Position::EMPTY,
            count: 32,
        },
    )
    .unwrap();
    let endpoint = Endpoint::parse("https://peer.vhalla.dev:443/vhalla/v1").unwrap();
    let cancel = AtomicBool::new(true);
    for (request, body) in [
        (stage_request, Some(stage.encode())),
        (commit_request, Some(commit.encode())),
        (status, None),
        (evidence, None),
    ] {
        assert!(request.target().len() <= wire::MAX_TARGET_BYTES);
        assert_eq!(
            continuity_bound(&request, body.as_deref()).unwrap(),
            wire::MAX_REPLY_BYTES
        );
        assert_eq!(
            exchange_continuity(&endpoint, &request, body.as_deref(), &cancel).unwrap_err(),
            "curl request cancelled"
        );
        assert_eq!(
            exchange(
                &endpoint,
                &request.target(),
                body.as_deref(),
                wire::MAX_REPLY_BYTES,
                &cancel
            )
            .unwrap_err(),
            "invalid bounded discovery transport request"
        );
    }
    assert!(continuity_bound(&stage_request, None).is_err());
    assert!(continuity_bound(&commit_request, None).is_err());
    assert!(continuity_bound(&status, Some(&[])).is_err());
    assert!(continuity_bound(&evidence, Some(&[])).is_err());
    let feed = wire::Request::new(
        context,
        wire::Selection::RoomFeed,
        wire::Kind::Feed {
            after: 0,
            count: 32,
        },
    )
    .unwrap();
    assert!(continuity_bound(&feed, None).is_err());
}

#[test]
fn continuity_http_body_maximum_and_exact_hash_scope_and_signature_checks() {
    let events = frames(33, true);
    let body = wire::Body::commit(events[..32].to_vec(), events[32].clone()).unwrap();
    let request = wire::Request::commit(
        context(&events[0]),
        events[0].claims().author,
        wire::Position::EMPTY,
        None,
        &body,
    )
    .unwrap();
    let raw = body.encode();
    assert_eq!(raw.len(), wire::MAX_BODY_BYTES);
    assert!(continuity_bound(&request, Some(&raw)).is_ok());
    let mut changed = raw.clone();
    *changed.last_mut().unwrap() ^= 1;
    let mut trailing = raw.clone();
    trailing.push(0);
    for bad in [&changed[..], &trailing[..], &raw[..raw.len() - 1]] {
        assert!(continuity_bound(&request, Some(bad)).is_err());
    }
    let wire::Kind::Commit {
        base,
        stage,
        terminal,
        terminal_frame,
        ..
    } = request.kind()
    else {
        panic!()
    };
    // Re-hashing malformed signed bytes does not bypass strict event decoding.
    use sha2::{Digest, Sha256};
    let forged = wire::Request::new(
        request.context(),
        request.selection(),
        wire::Kind::Commit {
            base,
            stage,
            terminal,
            terminal_frame,
            body: Sha256::digest(&changed).into(),
        },
    )
    .unwrap();
    assert!(continuity_bound(&forged, Some(&changed)).is_err());
    let mut foreign = request.context();
    foreign.scope.room[0] ^= 1;
    let foreign = wire::Request::new(foreign, request.selection(), request.kind()).unwrap();
    assert!(continuity_bound(&foreign, Some(&raw)).is_err());
}

#[test]
fn continuity_http_response_body_proof_and_header_ceilings_remain_independent() {
    fn response(proof: &str, body: &[u8]) -> Vec<u8> {
        let mut raw = format!("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nX-Vhalla-Proof: {proof}\r\n\r\n").into_bytes();
        raw.extend(body);
        raw
    }
    let proof_limit = wire::MAX_PROOF_BYTES * 2;
    assert_eq!(proof_limit, 1470);
    assert_eq!(wire::MAX_BODY_BYTES, 145008);
    assert_eq!(wire::MAX_REPLY_BYTES, 142176);
    assert_eq!(wire::MAX_TARGET_BYTES, 1230);
    let proof = "a".repeat(proof_limit);
    let body = vec![0; wire::MAX_REPLY_BYTES];
    assert_eq!(
        parse_response_with_limit(&response(&proof, &body), wire::MAX_REPLY_BYTES, proof_limit)
            .unwrap(),
        (body, proof)
    );
    assert!(parse_response_with_limit(
        &response(&"a".repeat(proof_limit + 1), b""),
        wire::MAX_REPLY_BYTES,
        proof_limit
    )
    .is_err());
    assert!(parse_response_with_limit(
        &response("ab", &vec![0; wire::MAX_REPLY_BYTES + 1]),
        wire::MAX_REPLY_BYTES,
        proof_limit
    )
    .is_err());
    let headers = format!("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nX-Vhalla-Proof: ab\r\nX-Padding: {}\r\n\r\n", "a".repeat(MAX_HEADERS));
    assert!(
        parse_response_with_limit(headers.as_bytes(), wire::MAX_REPLY_BYTES, proof_limit).is_err()
    );
}
