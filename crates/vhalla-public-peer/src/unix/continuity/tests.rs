use super::*;
use crate::unix::activity::tests::ActivityFixture;
use ed25519_dalek::SigningKey;
use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use vhalla_room_activity::{EventId, UnsignedEvent, VerifiedEvent};
use vhalla_room_activity_store::Limits;

fn config(f: &ActivityFixture) -> (Config, PathBuf, ContinuityConfig) {
    let directory = f.base.dir.join("continuity");
    let limits = ContinuityLimits {
        history: Limits {
            max_events: 200,
            max_history_bytes: 2_000_000,
        },
        max_stage_slots: 4,
        max_stage_events: 4096,
        max_stage_bytes: 32 * 1024 * 1024,
        stage_ttl_seconds: 3600,
    };
    drop(ContinuityStore::create(&directory, f.scope(), limits).unwrap());
    let state = f.base.dir.join("continuity-publisher");
    let mut config = f.base.config.clone();
    config.advertisement_file = state.join("advertisement");
    (
        config,
        state,
        ContinuityConfig {
            rooms: vec![ContinuityRoomConfig {
                room: f.room,
                directory,
                limits,
            }],
        },
    )
}
fn context(f: &ActivityFixture, nonce: u8) -> wire::RequestContext {
    wire::RequestContext {
        scope: f.scope().into(),
        nonce: [nonce; 32],
        operation: [nonce; 16],
        floor: wire::Observed {
            height: 0,
            frontier: f.genesis,
        },
    }
}
fn author() -> [u8; 32] {
    SigningKey::from_bytes(&[49; 32]).verifying_key().to_bytes()
}
fn history(f: &ActivityFixture, count: u64) -> Vec<VerifiedEvent> {
    let mut previous = EventId::ZERO;
    (1..=count)
        .map(|seq| {
            let event = SignedEvent::decode(&f.event(seq, previous, "synthetic history"))
                .unwrap()
                .verify()
                .unwrap();
            previous = event.id();
            event
        })
        .collect()
}
fn exchange(
    owner: &ManagedPeer,
    request: wire::Request,
    body: &[u8],
) -> Result<wire::Reply, StatusCode> {
    let peer = owner.peer_for_test();
    let reserved = peer.reserve_continuity(request, "127.0.0.1".parse().unwrap())?;
    let (body, proof) = peer.continuity_answer(reserved, body)?;
    let verified = wire::ResponseProof::from_hex(&proof)
        .unwrap()
        .verify(peer.application_key(), &request, &body)
        .unwrap();
    Ok(verified.reply().clone())
}
fn snapshot(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fn visit(root: &Path, path: &Path, out: &mut BTreeMap<PathBuf, Vec<u8>>) {
        for entry in fs::read_dir(path).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_dir() {
                visit(root, &entry.path(), out);
            } else {
                out.insert(
                    entry.path().strip_prefix(root).unwrap().to_owned(),
                    fs::read(entry.path()).unwrap(),
                );
            }
        }
    }
    let mut result = BTreeMap::new();
    visit(root, root, &mut result);
    result
}

#[test]
fn continuity_mode_is_exact_exclusive_and_refuses_mismatch_before_store_recovery() {
    let f = ActivityFixture::new();
    let (config, state, activity) = config(&f);
    let owner =
        ManagedPeer::create_with_continuity(config.clone(), &state, activity.clone()).unwrap();
    let marker = fs::read(state.join("activity-mode")).unwrap();
    assert_eq!(&marker[..5], b"VHPM\x02");
    drop(owner);
    let scratch = activity.rooms[0].directory.join("INTENT.tmp");
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&scratch)
        .unwrap();
    file.write_all(b"unpublished").unwrap();
    file.sync_all().unwrap();
    drop(file);
    let before = snapshot(&f.base.dir);
    assert!(ManagedPeer::open(config.clone(), &state).is_err());
    assert!(ManagedPeer::open_with_activity(config.clone(), &state, f.config.clone()).is_err());
    let mut foreign = activity.clone();
    foreign.rooms[0].limits.stage_ttl_seconds += 1;
    assert!(ManagedPeer::open_with_continuity(config.clone(), &state, foreign).is_err());
    assert!(ManagedPeer::create_with_continuity(config.clone(), &state, activity.clone()).is_err());
    assert_eq!(snapshot(&f.base.dir), before);
    // The exact mode can reconcile this unpublished scratch; it never resets a
    // descriptor sequence or adopts a legacy activity directory.
    let owner = ManagedPeer::open_with_continuity(config, &state, activity).unwrap();
    assert!(owner.advertisement_sequence().unwrap() > 1);
    assert!(!scratch.exists());
}

#[test]
fn continuity_new_mode_never_reinterprets_legacy_store_or_read_publisher() {
    let f = ActivityFixture::new();
    let (config, state, mut activity) = config(&f);
    let continuity = activity.clone();
    activity.rooms[0].directory = f.config.rooms[0].directory.clone();
    let before = snapshot(&activity.rooms[0].directory);
    assert!(ManagedPeer::create_with_continuity(config.clone(), &state, activity).is_err());
    assert!(!state.exists());
    assert_eq!(snapshot(&f.config.rooms[0].directory), before);
    let read = ManagedPeer::create(config.clone(), &state).unwrap();
    assert_eq!(
        read.current_public_advertisement()
            .unwrap()
            .unverified_claims()
            .capabilities,
        Capabilities::READ
    );
    drop(read);
    let before = snapshot(&f.base.dir);
    assert!(ManagedPeer::open_with_continuity(config.clone(), &state, continuity).is_err());
    assert_eq!(snapshot(&f.base.dir), before);
    let read = ManagedPeer::open(config, &state).unwrap();
    assert_eq!(
        read.current_public_advertisement()
            .unwrap()
            .unverified_claims()
            .capabilities,
        Capabilities::READ
    );
}

#[test]
fn continuity_staged_history_terminal_feed_and_revoked_restart_retry_preserve_roles() {
    let mut f = ActivityFixture::new();
    let (config, state, activity) = config(&f);
    let owner =
        ManagedPeer::create_with_continuity(config.clone(), &state, activity.clone()).unwrap();
    let events = history(&f, 65);
    let firstbody = wire::Body::stage(events[..32].to_vec()).unwrap();
    let first = wire::Request::stage(
        context(&f, 1),
        author(),
        wire::Position::EMPTY,
        None,
        &firstbody,
    )
    .unwrap();
    let wire::Reply::Staged(a) = exchange(&owner, first, &firstbody.encode()).unwrap() else {
        panic!("stage")
    };
    let secondbody = wire::Body::stage(events[32..64].to_vec()).unwrap();
    let second = wire::Request::stage(
        context(&f, 2),
        author(),
        wire::Position::EMPTY,
        Some(a.ticket),
        &secondbody,
    )
    .unwrap();
    let wire::Reply::Staged(b) = exchange(&owner, second, &secondbody.encode()).unwrap() else {
        panic!("stage")
    };
    assert_eq!(b.ticket.pages(), 2);
    let wire::Reply::Staged(retry) = exchange(&owner, first, &firstbody.encode()).unwrap() else {
        panic!("retry")
    };
    assert_eq!(retry.ticket, b.ticket);
    assert_eq!(retry.submitted_end, wire::Position::of(&events[31]));
    f.set_policy(false);
    f.set_policy(true);
    let terminal = SignedEvent::decode(&f.event(66, events[64].id(), "current terminal"))
        .unwrap()
        .verify()
        .unwrap();
    let body = wire::Body::commit(vec![events[64].clone()], terminal.clone()).unwrap();
    let request = wire::Request::commit(
        context(&f, 3),
        author(),
        wire::Position::EMPTY,
        Some(b.ticket),
        &body,
    )
    .unwrap();
    let wire::Reply::Committed(receipt) = exchange(&owner, request, &body.encode()).unwrap() else {
        panic!("terminal")
    };
    assert!(!receipt.reconciled);
    assert_eq!(receipt.cursor, 1);
    let other_key = SigningKey::from_bytes(&[50; 32]);
    let mut other_claims = terminal.claims().clone();
    other_claims.author = other_key.verifying_key().to_bytes();
    other_claims.sequence = 1;
    other_claims.previous = EventId::ZERO;
    let other = UnsignedEvent::new(other_claims)
        .unwrap()
        .sign_with_key(&other_key)
        .unwrap()
        .verify()
        .unwrap();
    let other_body = wire::Body::commit(vec![], other.clone()).unwrap();
    let other_request = wire::Request::commit(
        context(&f, 6),
        other.claims().author,
        wire::Position::EMPTY,
        None,
        &other_body,
    )
    .unwrap();
    assert!(matches!(
        exchange(&owner, other_request, &other_body.encode()),
        Ok(wire::Reply::Committed(_))
    ));
    let feed = wire::Request::new(
        context(&f, 4),
        wire::Selection::RoomFeed,
        wire::Kind::Feed {
            after: 0,
            count: 32,
        },
    )
    .unwrap();
    let wire::Reply::Feed(feed) = exchange(&owner, feed, &[]).unwrap() else {
        panic!("feed")
    };
    assert_eq!(feed.entries.len(), 2);
    assert_eq!(feed.entries[0].event, terminal);
    assert_eq!(feed.entries[1].event, other);
    let evidence = wire::Request::new(
        context(&f, 5),
        wire::Selection::Author(author()),
        wire::Kind::Evidence {
            after: wire::Position::of(&events[63]),
            count: 32,
        },
    )
    .unwrap();
    let wire::Reply::Evidence(evidence) = exchange(&owner, evidence, &[]).unwrap() else {
        panic!("evidence")
    };
    assert_eq!(evidence.entries.len(), 2);
    assert_eq!(
        evidence.entries[0].role,
        wire::EvidenceRole::HistoricalContinuity
    );
    assert_eq!(
        evidence.entries[1].role,
        wire::EvidenceRole::CurrentAdmission
    );
    drop(owner);
    f.set_policy(false);
    let owner = ManagedPeer::open_with_continuity(config, &state, activity).unwrap();
    let wire::Reply::Committed(retry) = exchange(&owner, request, &body.encode()).unwrap() else {
        panic!("retry")
    };
    assert!(retry.reconciled);
    assert_eq!(retry.registry, receipt.registry);
    assert_eq!(retry.cursor, 1);
}

#[test]
fn continuity_legacy_post_cannot_consume_staging_and_stale_ticket_cannot_commit() {
    let f = ActivityFixture::new();
    let (config, state, activity) = config(&f);
    let owner = ManagedPeer::create_with_continuity(config, &state, activity.clone()).unwrap();
    let events = history(&f, 64);
    let firstbody = wire::Body::stage(events[..32].to_vec()).unwrap();
    let first = wire::Request::stage(
        context(&f, 1),
        author(),
        wire::Position::EMPTY,
        None,
        &firstbody,
    )
    .unwrap();
    let wire::Reply::Staged(a) = exchange(&owner, first, &firstbody.encode()).unwrap() else {
        panic!("stage")
    };
    let raw = f.event(33, events[31].id(), "legacy must not finalize");
    let req = legacy::ActivityRequest::post([7; 32], *f.room.as_bytes(), &raw).unwrap();
    let before = snapshot(&activity.rooms[0].directory);
    assert!(matches!(
        owner
            .peer_for_test()
            .activity_answer(req, &raw, "127.0.0.1".parse().unwrap()),
        Err(StatusCode::CONFLICT)
    ));
    assert_eq!(snapshot(&activity.rooms[0].directory), before);
    let secondbody = wire::Body::stage(events[32..].to_vec()).unwrap();
    let second = wire::Request::stage(
        context(&f, 2),
        author(),
        wire::Position::EMPTY,
        Some(a.ticket),
        &secondbody,
    )
    .unwrap();
    exchange(&owner, second, &secondbody.encode()).unwrap();
    let terminal = SignedEvent::decode(&f.event(65, events[63].id(), "stale prefix"))
        .unwrap()
        .verify()
        .unwrap();
    let body = wire::Body::commit(events[32..].to_vec(), terminal).unwrap();
    let request = wire::Request::commit(
        context(&f, 3),
        author(),
        wire::Position::EMPTY,
        Some(a.ticket),
        &body,
    )
    .unwrap();
    let before = snapshot(&activity.rooms[0].directory);
    assert!(matches!(
        exchange(&owner, request, &body.encode()),
        Err(StatusCode::CONFLICT)
    ));
    assert_eq!(snapshot(&activity.rooms[0].directory), before);
}

#[test]
fn continuity_body_scope_floor_and_proof_mismatches_never_publish() {
    let f = ActivityFixture::new();
    let (config, state, activity) = config(&f);
    let owner = ManagedPeer::create_with_continuity(config, &state, activity.clone()).unwrap();
    let event = history(&f, 1).remove(0);
    let body = wire::Body::commit(vec![], event).unwrap();
    let request =
        wire::Request::commit(context(&f, 1), author(), wire::Position::EMPTY, None, &body)
            .unwrap();
    let before = snapshot(&activity.rooms[0].directory);
    let mut corrupt = body.encode();
    *corrupt.last_mut().unwrap() ^= 1;
    assert!(matches!(
        exchange(&owner, request, &corrupt),
        Err(StatusCode::BAD_REQUEST)
    ));
    assert_eq!(snapshot(&activity.rooms[0].directory), before);
    let mut ctx = context(&f, 2);
    ctx.scope.directory = [8; 32];
    let foreign = wire::Request::new(ctx, request.selection(), request.kind()).unwrap();
    assert!(matches!(
        exchange(&owner, foreign, &body.encode()),
        Err(StatusCode::BAD_REQUEST)
    ));
    let mut ctx = context(&f, 3);
    ctx.floor.frontier = [8; 32];
    let foreign = wire::Request::new(ctx, request.selection(), request.kind()).unwrap();
    assert!(matches!(
        exchange(&owner, foreign, &body.encode()),
        Err(StatusCode::CONFLICT)
    ));
    assert_eq!(snapshot(&activity.rooms[0].directory), before);
    let peer = owner.peer_for_test();
    let r = peer
        .reserve_continuity(request, "127.0.0.1".parse().unwrap())
        .unwrap();
    let (bytes, proof) = peer.continuity_answer(r, &body.encode()).unwrap();
    let proof = wire::ResponseProof::from_hex(&proof).unwrap();
    assert!(proof
        .verify(
            SigningKey::from_bytes(&[80; 32]).verifying_key().to_bytes(),
            &request,
            &bytes
        )
        .is_err());
    let changed = wire::Request::new(context(&f, 4), request.selection(), request.kind()).unwrap();
    assert!(proof
        .verify(peer.application_key(), &changed, &bytes)
        .is_err());
    let mut bad = bytes.to_vec();
    *bad.last_mut().unwrap() ^= 1;
    assert!(proof
        .verify(peer.application_key(), &request, &bad)
        .is_err());
}

#[test]
fn continuity_concurrent_exact_commits_return_one_retained_terminal() {
    let f = ActivityFixture::new();
    let (config, state, activity) = config(&f);
    let owner = ManagedPeer::create_with_continuity(config, &state, activity).unwrap();
    let body = wire::Body::commit(vec![], history(&f, 1).remove(0)).unwrap();
    let request =
        wire::Request::commit(context(&f, 1), author(), wire::Position::EMPTY, None, &body)
            .unwrap();
    let raw = body.encode();
    let barrier = std::sync::Barrier::new(2);
    std::thread::scope(|scope| {
        let tasks = (0..2)
            .map(|_| {
                scope.spawn(|| {
                    barrier.wait();
                    match exchange(&owner, request, &raw) {
                        Ok(wire::Reply::Committed(receipt)) => assert_eq!(receipt.cursor, 1),
                        Err(StatusCode::SERVICE_UNAVAILABLE) => {}
                        result => panic!("unexpected concurrent result: {result:?}"),
                    }
                })
            })
            .collect::<Vec<_>>();
        for task in tasks {
            task.join().unwrap();
        }
    });
    let wire::Reply::Committed(receipt) = exchange(&owner, request, &raw).unwrap() else {
        panic!("receipt");
    };
    assert!(receipt.reconciled);
    assert_eq!(receipt.cursor, 1);
    let feed = wire::Request::new(
        context(&f, 2),
        wire::Selection::RoomFeed,
        wire::Kind::Feed {
            after: 0,
            count: 32,
        },
    )
    .unwrap();
    let wire::Reply::Feed(feed) = exchange(&owner, feed, &[]).unwrap() else {
        panic!("feed");
    };
    assert_eq!(feed.tip, 1);
    assert_eq!(feed.entries.len(), 1);
}

#[test]
fn continuity_http_bounds_are_route_specific_and_keep_existing_header_deadlines() {
    let f = ActivityFixture::new();
    let (config, state, activity) = config(&f);
    let owner = ManagedPeer::create_with_continuity(config, &state, activity).unwrap();
    let events = history(&f, 32);
    let body = wire::Body::stage(events).unwrap();
    let request =
        wire::Request::stage(context(&f, 1), author(), wire::Position::EMPTY, None, &body).unwrap();
    let host = owner
        .peer_for_test()
        .config
        .public_endpoint
        .as_str()
        .strip_prefix("https://")
        .unwrap()
        .strip_suffix("/vhalla/v1")
        .unwrap();
    let http = |len| {
        Request::builder()
            .method(Method::POST)
            .uri(request.target())
            .header(header::HOST, host)
            .header(header::CONTENT_TYPE, "application/octet-stream")
            .header(header::CONTENT_LENGTH, len)
            .body(())
            .unwrap()
    };
    assert!(owner
        .peer_for_test()
        .check_continuity_request(&http(wire::MAX_BODY_BYTES))
        .is_ok());
    assert!(matches!(
        owner
            .peer_for_test()
            .check_continuity_request(&http(wire::MAX_BODY_BYTES + 1)),
        Err(StatusCode::PAYLOAD_TOO_LARGE)
    ));
    let mut bad = http(1);
    bad.headers_mut().append(
        header::CONTENT_LENGTH,
        header::HeaderValue::from_static("1"),
    );
    assert!(owner
        .peer_for_test()
        .check_continuity_request(&bad)
        .is_err());
    let mut bad = http(1);
    bad.headers_mut().insert(
        header::TRANSFER_ENCODING,
        header::HeaderValue::from_static("chunked"),
    );
    assert!(owner
        .peer_for_test()
        .check_continuity_request(&bad)
        .is_err());
    let mut bad = http(1);
    bad.headers_mut().insert(
        header::CONTENT_ENCODING,
        header::HeaderValue::from_static("gzip"),
    );
    assert!(owner
        .peer_for_test()
        .check_continuity_request(&bad)
        .is_err());
    assert_eq!(HEADER_BYTES, 8192);
    assert_eq!(READ_TIMEOUT, Duration::from_secs(10));
    assert_eq!(CONNECTION_TIMEOUT, Duration::from_secs(15));
    assert_eq!(wire::MAX_BODY_BYTES, 145008);
    assert_eq!(wire::MAX_REPLY_BYTES, 142176);
    assert_eq!(wire::MAX_PROOF_BYTES * 2, 1470);
    assert_eq!(wire::MAX_TARGET_BYTES, 1230);
}

#[test]
fn continuity_refresh_refuses_raced_policy_and_resumes_bounded_certified_catchup() {
    let mut f = ActivityFixture::new();
    for _ in 0..33 {
        f.set_policy(true);
    }
    let (config, state, activity) = config(&f);
    let owner = ManagedPeer::create_with_continuity(config, &state, activity.clone()).unwrap();
    let body = wire::Body::commit(vec![], history(&f, 1).remove(0)).unwrap();
    let request =
        wire::Request::commit(context(&f, 1), author(), wire::Position::EMPTY, None, &body)
            .unwrap();
    assert!(matches!(
        exchange(&owner, request, &body.encode()),
        Err(StatusCode::SERVICE_UNAVAILABLE)
    ));
    {
        let slot = owner.peer_for_test().activity.lock().unwrap();
        let Some(activity::Owner::Continuity(service)) = slot.as_ref() else {
            panic!("mode");
        };
        assert_eq!(
            service.client.frontier().height,
            ACTIVITY_REPLAY_BUDGET as u64
        );
        assert_eq!(service.stores[f.room.as_bytes()].pin().feed_count(), 0);
    }
    let fixture = Arc::new(Mutex::new(f));
    let writer = fixture.clone();
    {
        let mut slot = owner.peer_for_test().activity.lock().unwrap();
        let Some(activity::Owner::Continuity(service)) = slot.as_mut() else {
            panic!("mode");
        };
        service.after_refresh = Some(Box::new(move || writer.lock().unwrap().set_policy(false)));
    }
    let before = snapshot(&activity.rooms[0].directory);
    assert!(matches!(
        exchange(&owner, request, &body.encode()),
        Err(StatusCode::SERVICE_UNAVAILABLE)
    ));
    assert_eq!(snapshot(&activity.rooms[0].directory), before);
    assert!(matches!(
        exchange(&owner, request, &body.encode()),
        Err(StatusCode::FORBIDDEN)
    ));
    fixture.lock().unwrap().set_policy(true);
    let f = fixture.lock().unwrap();
    let current = wire::Body::commit(vec![], history(&f, 1).remove(0)).unwrap();
    let current_request = wire::Request::commit(
        context(&f, 2),
        author(),
        wire::Position::EMPTY,
        None,
        &current,
    )
    .unwrap();
    assert!(matches!(
        exchange(&owner, current_request, &current.encode()),
        Ok(wire::Reply::Committed(_))
    ));
}

#[test]
fn continuity_expired_status_is_read_only_and_cleanup_requires_separate_credit() {
    let f = ActivityFixture::new();
    let (config, state, activity) = config(&f);
    let owner = ManagedPeer::create_with_continuity(config, &state, activity.clone()).unwrap();
    let body = wire::Body::stage(history(&f, 32)).unwrap();
    let request =
        wire::Request::stage(context(&f, 1), author(), wire::Position::EMPTY, None, &body).unwrap();
    let wire::Reply::Staged(ack) = exchange(&owner, request, &body.encode()).unwrap() else {
        panic!("stage");
    };
    let clock = ack.ticket.expires_at();
    let status = wire::Request::new(
        context(&f, 2),
        wire::Selection::Author(author()),
        wire::Kind::Status {
            minimum: wire::Position::EMPTY,
        },
    )
    .unwrap();
    let peer = owner.peer_for_test();
    let reservation = peer
        .reserve_continuity(status, "127.0.0.1".parse().unwrap())
        .unwrap();
    let before = snapshot(&activity.rooms[0].directory);
    let mut slot = peer.activity.lock().unwrap();
    let Some(activity::Owner::Continuity(service)) = slot.as_mut() else {
        panic!("mode");
    };
    let reply = service.answer(peer, reservation, &[], clock).unwrap();
    let wire::Reply::Status(status) = wire::Reply::decode(&reply, &status).unwrap() else {
        panic!("status");
    };
    assert_eq!(status.published, wire::Position::EMPTY);
    assert!(status.stage.is_none());
    assert_eq!(snapshot(&activity.rooms[0].directory), before);
    assert!(service.rate.charge(
        None,
        Cost {
            cleanup: 128,
            ..Cost::default()
        },
        Instant::now()
    ));
    service.maintain(clock).unwrap();
    assert_eq!(snapshot(&activity.rooms[0].directory), before);
    service.rate = Rate::new();
    service.maintain(clock).unwrap();
    let store = &service.stores[f.room.as_bytes()];
    assert_eq!(
        store
            .author_status(author(), clock)
            .unwrap()
            .cleanup_pages(),
        0
    );
    assert!(store.author_status(author(), clock - 1).is_err());
    assert_eq!(store.pin().feed_count(), 0);
}

#[test]
fn continuity_exhausted_fixed_credit_refuses_before_replay_or_corrupt_tail_read() {
    let f = ActivityFixture::new();
    let (config, state, activity) = config(&f);
    let owner = ManagedPeer::create_with_continuity(config, &state, activity.clone()).unwrap();
    let body = wire::Body::stage(history(&f, 32)).unwrap();
    let request =
        wire::Request::stage(context(&f, 1), author(), wire::Position::EMPTY, None, &body).unwrap();
    exchange(&owner, request, &body.encode()).unwrap();
    let ip = "127.0.0.1".parse().unwrap();
    {
        let mut slot = owner.peer_for_test().activity.lock().unwrap();
        let Some(activity::Owner::Continuity(service)) = slot.as_mut() else {
            panic!("mode");
        };
        assert!(service.rate.charge(
            Some(ip),
            Cost {
                stored: 4096 - rate::request_cost(request.kind()).stored,
                ..Cost::default()
            },
            Instant::now()
        ));
        service.after_refresh = Some(Box::new(|| {
            panic!("quota refusal must precede certified refresh")
        }));
    }
    let page = fs::read_dir(activity.rooms[0].directory.join("pages"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let mut raw = fs::read(&page).unwrap();
    *raw.last_mut().unwrap() ^= 1;
    fs::write(&page, raw).unwrap();
    let before = snapshot(&activity.rooms[0].directory);
    assert!(matches!(
        exchange(&owner, request, &body.encode()),
        Err(StatusCode::TOO_MANY_REQUESTS)
    ));
    assert_eq!(snapshot(&activity.rooms[0].directory), before);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn continuity_real_http_proof_chunked_bound_and_slow_body_deadline() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let f = ActivityFixture::new();
    let (config, state, activity) = config(&f);
    let owner = Arc::new(ManagedPeer::create_with_continuity(config, &state, activity).unwrap());
    let body = wire::Body::commit(vec![], history(&f, 1).remove(0)).unwrap();
    let request =
        wire::Request::commit(context(&f, 1), author(), wire::Position::EMPTY, None, &body)
            .unwrap();
    let raw = body.encode();
    let bound = owner.clone().bind().await.unwrap();
    let address = bound.local_addr().unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(bound.run(async {
        let _ = stopped.await;
    }));
    let mut post = format!("POST {} HTTP/1.1\r\nHost: peer.vhalla.dev\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n\r\n", request.target(), raw.len()).into_bytes();
    post.extend(raw);
    let mut socket = tokio::net::TcpStream::connect(address).await.unwrap();
    socket.write_all(&post).await.unwrap();
    let mut response = Vec::new();
    timeout(Duration::from_secs(10), socket.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert!(
        response.starts_with(b"HTTP/1.1 200"),
        "{}",
        String::from_utf8_lossy(&response)
    );
    let split = response.windows(4).position(|v| v == b"\r\n\r\n").unwrap();
    let headers = std::str::from_utf8(&response[..split]).unwrap();
    let proof = headers
        .lines()
        .find_map(|line| line.strip_prefix("x-vhalla-proof: "))
        .unwrap()
        .trim();
    let verified = wire::ResponseProof::from_hex(proof)
        .unwrap()
        .verify(owner.application_key(), &request, &response[split + 4..])
        .unwrap();
    assert!(matches!(verified.reply(), wire::Reply::Committed(_)));

    let prefix = format!("POST {} HTTP/1.1\r\nHost: peer.vhalla.dev\r\nContent-Type: application/octet-stream\r\nTransfer-Encoding: chunked\r\n\r\n", request.target());
    let mut socket = tokio::net::TcpStream::connect(address).await.unwrap();
    let oversized = format!(
        "{prefix}{:x}\r\n{}\r\n0\r\n\r\n",
        wire::MAX_BODY_BYTES + 1,
        "x".repeat(wire::MAX_BODY_BYTES + 1)
    );
    // An early 413 can close the connection while the sender is still draining.
    let _ = socket.write_all(oversized.as_bytes()).await;
    let mut response = Vec::new();
    let _ = timeout(Duration::from_secs(10), socket.read_to_end(&mut response))
        .await
        .unwrap();
    assert!(
        response.starts_with(b"HTTP/1.1 413"),
        "{}",
        String::from_utf8_lossy(&response)
    );
    let mut socket = tokio::net::TcpStream::connect(address).await.unwrap();
    socket.write_all(prefix.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    timeout(Duration::from_secs(9), socket.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert!(
        response.starts_with(b"HTTP/1.1 408"),
        "{}",
        String::from_utf8_lossy(&response)
    );
    stop.send(()).unwrap();
    server.await.unwrap().unwrap();
}
