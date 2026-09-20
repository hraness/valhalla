use super::*;
use alloc::vec;
use vhalla_core::RealmId;
use vhalla_room_activity::{Content, EventClaims, Text, UnsignedEvent};
use vhalla_rooms::{DirectoryId, RoomGenesisId, RoomRecordId};

fn scope() -> RoomScope {
    RoomScope {
        network: [1; 32],
        realm: RealmId(7),
        directory: DirectoryId::from_bytes([3; 32]),
        room: RoomGenesisId::from_bytes([4; 32]),
    }
}
fn observed() -> Observed {
    Observed {
        height: 7,
        frontier: [8; 32],
    }
}
fn context() -> RequestContext {
    RequestContext {
        scope: scope().into(),
        nonce: [9; 32],
        operation: [10; 16],
        floor: observed(),
    }
}
fn author() -> SigningKey {
    SigningKey::from_bytes(&[11; 32])
}
fn event(s: RoomScope, key: &SigningKey, n: u64, prev: EventId, text: &str) -> VerifiedEvent {
    UnsignedEvent::new(EventClaims {
        scope: s,
        policy: RoomRecordId::from_bytes([12; 32]),
        author: key.verifying_key().to_bytes(),
        sequence: n,
        previous: prev,
        created_at: 13,
        content: Content::Text(Text::new(text).unwrap()),
    })
    .unwrap()
    .sign_with_key(key)
    .unwrap()
    .verify()
    .unwrap()
}
fn chain(n: usize) -> Vec<VerifiedEvent> {
    let mut events = Vec::with_capacity(n);
    let mut prev = EventId::ZERO;
    for i in 0..n {
        let e = event(
            scope(),
            &author(),
            i as u64 + 1,
            prev,
            "inert public activity",
        );
        prev = e.id();
        events.push(e);
    }
    events
}
fn status_request() -> Request {
    Request::new(
        context(),
        Selection::Author(author().verifying_key().to_bytes()),
        Kind::Status {
            minimum: Position::EMPTY,
        },
    )
    .unwrap()
}
fn stage_request() -> (Body, Request) {
    let body = Body::stage(chain(32)).unwrap();
    let r = Request::stage(
        context(),
        author().verifying_key().to_bytes(),
        Position::EMPTY,
        None,
        &body,
    )
    .unwrap();
    (body, r)
}
fn status_reply() -> Reply {
    Reply::Status(Status {
        observed: observed(),
        published: Position::EMPTY,
        stage: None,
    })
}
fn receipt(request: &Request, event: VerifiedEvent) -> Reply {
    let r = Reply::Committed(Box::new(TerminalReceipt {
        observed: observed(),
        event,
        cursor: 1,
        registry: [14; 32],
        reconciled: false,
    }));
    r.encode(request).unwrap();
    r
}
fn entry(event: VerifiedEvent, role: EvidenceRole, committed_by: u64) -> Entry {
    Entry {
        role,
        event,
        committed_by,
        registry: [14; 32],
    }
}

#[test]
fn canonical_requests_strict_selection_and_all_operations_roundtrip() {
    let (body, stage) = stage_request();
    let events = chain(33);
    let ticket = StageRef::new(
        [15; 32],
        Position::EMPTY,
        Position::of(&events[31]),
        1,
        1000,
    )
    .unwrap();
    let commit_body = Body::commit(vec![], events[32].clone()).unwrap();
    let commit = Request::commit(
        context(),
        author().verifying_key().to_bytes(),
        Position::EMPTY,
        Some(ticket),
        &commit_body,
    )
    .unwrap();
    let feed = Request::new(
        context(),
        Selection::RoomFeed,
        Kind::Feed {
            after: 0,
            count: 32,
        },
    )
    .unwrap();
    let evidence = Request::new(
        context(),
        stage.selection(),
        Kind::Evidence {
            after: Position::EMPTY,
            count: 32,
        },
    )
    .unwrap();
    for r in [stage, commit, status_request(), feed, evidence] {
        assert_eq!(Request::decode(&r.encode()).unwrap(), r);
        assert_eq!(Request::parse_target(&r.target()).unwrap(), r);
        assert!(r.encode().len() <= MAX_REQUEST_BYTES);
        assert!(r.target().len() <= MAX_TARGET_BYTES);
        for n in 0..r.encode().len() {
            assert!(Request::decode(&r.encode()[..n]).is_err());
        }
        let mut extra = r.encode();
        extra.push(0);
        assert!(Request::decode(&extra).is_err());
        assert!(Request::parse_target(&format!("{}&extra=1", r.target())).is_err());
        assert!(Request::parse_target(&r.target().to_uppercase()).is_err());
    }
    assert_eq!(stage.method(), "POST");
    assert_eq!(feed.method(), "GET");
    assert!(feed.check_body(&body.encode()).is_err());
    assert!(Request::new(
        context(),
        Selection::Author(author().verifying_key().to_bytes()),
        Kind::Feed { after: 0, count: 1 }
    )
    .is_err());
    assert!(Request::new(
        context(),
        Selection::RoomFeed,
        Kind::Status {
            minimum: Position::EMPTY
        }
    )
    .is_err());
    assert!(Request::new(
        context(),
        Selection::Author([0; 32]),
        Kind::Status {
            minimum: Position::EMPTY
        }
    )
    .is_err());
    for count in [0, 33, 255] {
        assert!(Request::new(
            context(),
            Selection::RoomFeed,
            Kind::Feed { after: 0, count }
        )
        .is_err());
    }
    let mut c = context();
    c.nonce = [0; 32];
    assert!(Request::new(c, feed.selection(), feed.kind()).is_err());
    c = context();
    c.operation = [0; 16];
    assert!(Request::new(c, feed.selection(), feed.kind()).is_err());
    c = context();
    c.scope.network = [0; 32];
    assert!(Request::new(c, feed.selection(), feed.kind()).is_err());
    c = context();
    c.floor.frontier = [0; 32];
    assert!(Request::new(c, feed.selection(), feed.kind()).is_err());
}

#[test]
fn mutation_shapes_signatures_exact_scope_and_chain_are_checked() {
    let (body, request) = stage_request();
    assert_eq!(request.check_body(&body.encode()).unwrap(), body);
    assert!(Body::stage(chain(31)).is_err());
    assert!(Body::stage(chain(33)).is_err());
    let events = chain(34);
    assert!(Body::commit(events[..33].to_vec(), events[33].clone()).is_err());
    for n in [0, 1, 32] {
        let events = chain(n + 1);
        let body = Body::commit(events[..n].to_vec(), events[n].clone()).unwrap();
        let r = Request::commit(
            context(),
            author().verifying_key().to_bytes(),
            Position::EMPTY,
            None,
            &body,
        )
        .unwrap();
        assert_eq!(r.check_body(&body.encode()).unwrap(), body);
    }
    let mut events = chain(32);
    events.swap(0, 1);
    let b = Body::stage(events).unwrap();
    assert!(Request::stage(
        context(),
        author().verifying_key().to_bytes(),
        Position::EMPTY,
        None,
        &b
    )
    .is_err());
    let mut events = chain(32);
    events[1] = events[0].clone();
    let b = Body::stage(events).unwrap();
    assert!(Request::stage(
        context(),
        author().verifying_key().to_bytes(),
        Position::EMPTY,
        None,
        &b
    )
    .is_err());
    for field in 0..5 {
        let mut s = scope();
        let key = if field == 4 {
            SigningKey::from_bytes(&[19; 32])
        } else {
            author()
        };
        match field {
            0 => s.network[0] ^= 1,
            1 => s.realm = RealmId(8),
            2 => s.directory = DirectoryId::from_bytes([20; 32]),
            3 => s.room = RoomGenesisId::from_bytes([21; 32]),
            _ => {}
        }
        let e = event(s, &key, 1, EventId::ZERO, "foreign");
        let b = Body::commit(vec![], e).unwrap();
        assert!(Request::commit(
            context(),
            author().verifying_key().to_bytes(),
            Position::EMPTY,
            None,
            &b
        )
        .is_err());
    }
    let mut raw = body.encode();
    let last = raw.len() - 1;
    raw[last] ^= 1;
    // Rebinding the request hash cannot turn a bad signature into a verified event.
    let Kind::Stage {
        base, prior, end, ..
    } = request.kind()
    else {
        unreachable!()
    };
    let r = Request::new(
        context(),
        request.selection(),
        Kind::Stage {
            base,
            prior,
            end,
            body: hash(&raw),
        },
    )
    .unwrap();
    assert!(r.check_body(&raw).is_err());
}

#[test]
fn mutation_decode_bounds_precede_allocation_and_never_ignore_trailing_bytes() {
    let body = Body::commit(vec![], chain(1).remove(0)).unwrap();
    let raw = body.encode();
    for n in 0..raw.len() {
        assert!(Body::decode(&raw[..n]).is_err());
    }
    let mut extra = raw.clone();
    extra.push(0);
    assert!(Body::decode(&extra).is_err());
    let mut count = raw.clone();
    count[5] = 255;
    assert!(Body::decode(&count).is_err());
    let mut len = raw.clone();
    len[6..8].copy_from_slice(&u16::MAX.to_be_bytes());
    assert!(Body::decode(&len).is_err());
    assert!(Body::decode(&vec![0; MAX_BODY_BYTES + 1]).is_err());
    let text = "x".repeat(vhalla_room_activity::MAX_TEXT_BYTES);
    let mut events = Vec::new();
    let mut prev = EventId::ZERO;
    for i in 1..=33 {
        let e = event(scope(), &author(), i, prev, &text);
        prev = e.id();
        events.push(e);
    }
    let terminal = events.pop().unwrap();
    let max = Body::commit(events, terminal).unwrap();
    assert_eq!(max.encode().len(), MAX_BODY_BYTES);
    assert!(Body::decode(&max.encode()).is_ok());
}

#[test]
fn positions_stage_tickets_and_counter_overflow_fail_closed() {
    assert!(Position::new(1, EventId::ZERO).is_err());
    assert!(Position::new(0, EventId::from_bytes([1; 32])).is_err());
    let end = Position::new(32, EventId::from_bytes([1; 32])).unwrap();
    for (id, pages, expiry) in [
        ([0; 32], 1, 1),
        ([1; 32], 0, 1),
        ([1; 32], 129, 1),
        ([1; 32], 1, 0),
    ] {
        assert!(StageRef::new(id, Position::EMPTY, end, pages, expiry).is_err());
    }
    assert!(StageRef::new([1; 32], Position::EMPTY, end, 2, 1).is_err());
    let base = Position::new(u64::MAX, EventId::from_bytes([2; 32])).unwrap();
    assert!(StageRef::new([1; 32], base, end, 1, 1).is_err());
    assert!(Request::new(
        context(),
        status_request().selection(),
        Kind::Commit {
            base,
            stage: None,
            terminal: base,
            terminal_frame: [1; 32],
            body: [1; 32]
        }
    )
    .is_err());
}

#[test]
fn stage_ack_binds_submitted_page_separately_from_aggregate_status() {
    let (_, request) = stage_request();
    let events = chain(64);
    let end = Position::of(&events[31]);
    let ticket = StageRef::new(
        [15; 32],
        Position::EMPTY,
        Position::of(&events[63]),
        2,
        1000,
    )
    .unwrap();
    let Kind::Stage { body, .. } = request.kind() else {
        unreachable!()
    };
    let ack = StageAck {
        observed: observed(),
        base: Position::EMPTY,
        ticket,
        submitted_end: end,
        submitted_body: body,
    };
    let reply = Reply::Staged(ack.clone());
    assert_eq!(
        Reply::decode(&reply.encode(&request).unwrap(), &request).unwrap(),
        reply
    );
    let mut wrong = ack.clone();
    wrong.submitted_end = ticket.tail();
    assert!(Reply::Staged(wrong).encode(&request).is_err());
    let mut wrong = ack;
    wrong.submitted_body[0] ^= 1;
    assert!(Reply::Staged(wrong).encode(&request).is_err());
    let prior = StageRef::new([15; 32], Position::EMPTY, end, 1, 1000).unwrap();
    let b = Body::stage(events[32..].to_vec()).unwrap();
    let next = Request::stage(
        context(),
        author().verifying_key().to_bytes(),
        Position::EMPTY,
        Some(prior),
        &b,
    )
    .unwrap();
    let Kind::Stage { end, body, .. } = next.kind() else {
        unreachable!()
    };
    for (id, expiry) in [([16; 32], 1000), ([15; 32], 1001)] {
        let ticket = StageRef::new(id, Position::EMPTY, end, 2, expiry).unwrap();
        let r = Reply::Staged(StageAck {
            observed: observed(),
            base: Position::EMPTY,
            ticket,
            submitted_end: end,
            submitted_body: body,
        });
        assert!(r.encode(&next).is_err());
    }
}

#[test]
fn terminal_receipt_is_exact_terminal_only_and_does_not_promote_history() {
    let mut events = chain(33);
    let terminal = events.pop().unwrap();
    let body = Body::commit(events.clone(), terminal.clone()).unwrap();
    let r = Request::commit(
        context(),
        author().verifying_key().to_bytes(),
        Position::EMPTY,
        None,
        &body,
    )
    .unwrap();
    let reply = receipt(&r, terminal);
    let raw = reply.encode(&r).unwrap();
    assert_eq!(Reply::decode(&raw, &r).unwrap(), reply);
    let Reply::Committed(mut wrong) = reply.clone() else {
        unreachable!()
    };
    wrong.event = events[0].clone();
    assert!(Reply::Committed(wrong).encode(&r).is_err());
    let Reply::Committed(mut retry) = reply else {
        unreachable!()
    };
    retry.reconciled = true;
    retry.observed = Observed {
        height: 100,
        frontier: [42; 32],
    };
    assert!(Reply::Committed(retry).encode(&r).is_ok());
    assert!(crate::activity::LocalReceipt::decode(&raw).is_err());
    let (_, stage) = stage_request();
    assert!(Reply::decode(&raw, &stage).is_err());
}

#[test]
fn room_feed_accepts_multiple_authors_but_no_historical_or_foreign_events() {
    let r = Request::new(
        context(),
        Selection::RoomFeed,
        Kind::Feed { after: 0, count: 2 },
    )
    .unwrap();
    let a = chain(1).remove(0);
    let b = event(
        scope(),
        &SigningKey::from_bytes(&[22; 32]),
        1,
        EventId::ZERO,
        "another author",
    );
    let page = FeedPage {
        observed: observed(),
        tip: 2,
        entries: vec![
            entry(a, EvidenceRole::CurrentAdmission, 1),
            entry(b, EvidenceRole::CurrentAdmission, 2),
        ],
    };
    let reply = Reply::Feed(page.clone());
    assert_eq!(
        Reply::decode(&reply.encode(&r).unwrap(), &r).unwrap(),
        reply
    );
    let mut p = page.clone();
    p.entries[0].role = EvidenceRole::HistoricalContinuity;
    assert!(Reply::Feed(p).encode(&r).is_err());
    let mut p = page.clone();
    p.entries[1].committed_by = 1;
    assert!(Reply::Feed(p).encode(&r).is_err());
    let mut p = page.clone();
    p.entries[1].event = p.entries[0].event.clone();
    assert!(Reply::Feed(p).encode(&r).is_err());
    let mut p = page.clone();
    p.entries[1].event = event(scope(), &author(), 1, EventId::ZERO, "same sequence fork");
    assert!(Reply::Feed(p).encode(&r).is_err());
    let mut p = page.clone();
    p.entries.clear();
    assert!(Reply::Feed(p).encode(&r).is_err());
    let mut p = page;
    let mut s = scope();
    s.network = [55; 32];
    p.entries[1].event = event(s, &author(), 1, EventId::ZERO, "wrong");
    assert!(Reply::Feed(p).encode(&r).is_err());
}

#[test]
fn evidence_pages_bind_full_author_previous_id_and_immutable_roles() {
    let events = chain(4);
    let r = Request::new(
        context(),
        status_request().selection(),
        Kind::Evidence {
            after: Position::EMPTY,
            count: 4,
        },
    )
    .unwrap();
    let p = EvidencePage {
        observed: observed(),
        tip: Position::of(&events[3]),
        entries: vec![
            entry(events[0].clone(), EvidenceRole::HistoricalContinuity, 1),
            entry(events[1].clone(), EvidenceRole::CurrentAdmission, 1),
            entry(events[2].clone(), EvidenceRole::HistoricalContinuity, 2),
            entry(events[3].clone(), EvidenceRole::CurrentAdmission, 2),
        ],
    };
    let reply = Reply::Evidence(p.clone());
    assert_eq!(
        Reply::decode(&reply.encode(&r).unwrap(), &r).unwrap(),
        reply
    );
    let mut wrong = p.clone();
    wrong.entries[1].committed_by = 2;
    assert!(Reply::Evidence(wrong).encode(&r).is_err());
    let mut wrong = p.clone();
    wrong.entries[2].committed_by = 1;
    assert!(Reply::Evidence(wrong).encode(&r).is_err());
    let mut wrong = p.clone();
    wrong.entries[3].role = EvidenceRole::HistoricalContinuity;
    assert!(Reply::Evidence(wrong).encode(&r).is_err());
    let mut wrong = p.clone();
    wrong.entries.swap(0, 1);
    assert!(Reply::Evidence(wrong).encode(&r).is_err());
    let after = Position::new(2, EventId::from_bytes([66; 32])).unwrap();
    let wrong = Request::new(context(), r.selection(), Kind::Evidence { after, count: 2 }).unwrap();
    let suffix = Reply::Evidence(EvidencePage {
        observed: observed(),
        tip: p.tip,
        entries: p.entries[2..].to_vec(),
    });
    assert!(suffix.encode(&wrong).is_err());
    let foreign = Request::new(
        context(),
        Selection::Author(SigningKey::from_bytes(&[33; 32]).verifying_key().to_bytes()),
        r.kind(),
    )
    .unwrap();
    assert!(reply.encode(&foreign).is_err());
}

#[test]
fn requested_certified_floor_and_author_floor_cannot_regress_or_equivocate() {
    let r = status_request();
    let mut s = Status {
        observed: observed(),
        published: Position::EMPTY,
        stage: None,
    };
    s.observed.height -= 1;
    assert!(Reply::Status(s.clone()).encode(&r).is_err());
    s.observed = observed();
    s.observed.frontier[0] ^= 1;
    assert!(Reply::Status(s.clone()).encode(&r).is_err());
    s.observed = Observed {
        height: 8,
        frontier: [55; 32],
    };
    assert!(Reply::Status(s).encode(&r).is_ok());
    let e = chain(1).remove(0);
    let minimum = Position::of(&e);
    let r = Request::new(context(), r.selection(), Kind::Status { minimum }).unwrap();
    assert!(status_reply().encode(&r).is_err());
    let p = Position::new(1, EventId::from_bytes([66; 32])).unwrap();
    assert!(Reply::Status(Status {
        observed: observed(),
        published: p,
        stage: None
    })
    .encode(&r)
    .is_err());
}

#[test]
fn proof_authenticates_every_byte_and_cannot_cross_request_or_role_domains() {
    let request = status_request();
    let body = status_reply().encode(&request).unwrap();
    let key = SigningKey::from_bytes(&[44; 32]);
    let peer = key.verifying_key().to_bytes();
    let proof = UnsignedResponse::new(peer, request, &body)
        .unwrap()
        .sign_with_key(&key)
        .unwrap();
    let verified = proof.verify(peer, &request, &body).unwrap();
    assert_eq!(verified.request(), request);
    assert_eq!(verified.peer(), peer);
    assert_eq!(verified.reply(), &status_reply());
    let raw = proof.encode();
    assert_eq!(
        ResponseProof::from_hex(&crate::response::hex(&raw)).unwrap(),
        proof
    );
    for at in 0..raw.len() {
        let mut changed = raw.clone();
        changed[at] ^= 1;
        assert!(
            ResponseProof::decode(&changed)
                .and_then(|p| p.verify(peer, &request, &body))
                .is_err(),
            "proof byte {at}"
        );
    }
    for at in 0..body.len() {
        let mut changed = body.clone();
        changed[at] ^= 1;
        assert!(proof.verify(peer, &request, &changed).is_err());
    }
    for field in 0..8 {
        let mut c = context();
        match field {
            0 => c.nonce[0] ^= 1,
            1 => c.operation[0] ^= 1,
            2 => c.scope.network[0] ^= 1,
            3 => c.scope.realm[0] ^= 1,
            4 => c.scope.directory[0] ^= 1,
            5 => c.scope.room[0] ^= 1,
            6 => c.floor.height += 1,
            _ => c.floor.frontier[0] ^= 1,
        };
        let wrong = Request::new(c, request.selection(), request.kind()).unwrap();
        assert!(proof.verify(peer, &wrong, &body).is_err());
    }
    let foreign = SigningKey::from_bytes(&[45; 32]);
    assert!(proof
        .verify(foreign.verifying_key().to_bytes(), &request, &body)
        .is_err());
    assert!(UnsignedResponse::new(peer, request, &body)
        .unwrap()
        .sign_with_key(&foreign)
        .is_err());
    assert!(UnsignedResponse::new([0; 32], request, &body).is_err());
    let mut alternate = b"vhalla/public-activity-response/v1\0".to_vec();
    alternate.extend(proof.statement.unsigned());
    let sig = key.sign(&alternate).to_bytes();
    assert!(proof.statement.clone().attach_signature(sig).is_err());
    assert!(crate::activity::ActivityResponseProof::decode(&raw).is_err());
    assert!(ResponseProof::from_hex(&crate::response::hex(&raw).to_uppercase()).is_err());
    for n in 0..raw.len() {
        assert!(ResponseProof::decode(&raw[..n]).is_err());
    }
}

#[test]
fn response_declared_counts_lengths_tags_and_trailing_bytes_are_bounded() {
    let r = Request::new(
        context(),
        Selection::RoomFeed,
        Kind::Feed { after: 0, count: 1 },
    )
    .unwrap();
    let reply = Reply::Feed(FeedPage {
        observed: observed(),
        tip: 1,
        entries: vec![entry(chain(1).remove(0), EvidenceRole::CurrentAdmission, 1)],
    });
    let raw = reply.encode(&r).unwrap();
    for n in 0..raw.len() {
        assert!(Reply::decode(&raw[..n], &r).is_err());
    }
    let mut extra = raw.clone();
    extra.push(0);
    assert!(Reply::decode(&extra, &r).is_err());
    let mut count = raw.clone();
    count[54] = 255;
    assert!(Reply::decode(&count, &r).is_err());
    let mut role = raw.clone();
    role[55] = 2;
    assert!(Reply::decode(&role, &r).is_err());
    let mut len = raw;
    len[96..98].copy_from_slice(&u16::MAX.to_be_bytes());
    assert!(Reply::decode(&len, &r).is_err());
    assert!(Reply::decode(&vec![0; MAX_REPLY_BYTES + 1], &r).is_err());
}

#[test]
fn terminal_full_signed_frame_hash_is_separate_from_unsigned_content_id() {
    let terminal = chain(1).remove(0);
    let body = Body::commit(vec![], terminal.clone()).unwrap();
    let request = Request::commit(
        context(),
        author().verifying_key().to_bytes(),
        Position::EMPTY,
        None,
        &body,
    )
    .unwrap();
    let reply = receipt(&request, terminal);
    let Kind::Commit {
        base,
        stage,
        terminal,
        mut terminal_frame,
        body: body_hash,
    } = request.kind()
    else {
        unreachable!()
    };
    terminal_frame[0] ^= 1;
    let wrong = Request::new(
        context(),
        request.selection(),
        Kind::Commit {
            base,
            stage,
            terminal,
            terminal_frame,
            body: body_hash,
        },
    )
    .unwrap();
    assert!(wrong.check_body(&body.encode()).is_err());
    assert!(reply.encode(&wrong).is_err());
    assert_eq!(Request::decode(&request.encode()).unwrap(), request);
}
