//! Direct-only loopback peers, hostile framing and owned shutdown qualification.

use super::*;
use iroh::SecretKey;
use std::sync::{
    atomic::{AtomicBool, AtomicU8, Ordering},
    Mutex,
};
use vhalla_direct_room::PinnedGenesis;
use vhalla_direct_sync::{Coverage, Page, Receiver, SourceAccumulator};

fn run(future: impl Future<Output = ()>) {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            timeout(Duration::from_secs(25), future)
                .await
                .expect("bounded loopback test")
        });
}
async fn endpoint(server: bool) -> Endpoint {
    static NEXT_KEY: AtomicU8 = AtomicU8::new(40);
    endpoint_builder()
        .secret_key(SecretKey::from_bytes(
            &[NEXT_KEY.fetch_add(1, Ordering::Relaxed); 32],
        ))
        .alpns(if server { vec![ALPN.to_vec()] } else { vec![] })
        .clear_ip_transports()
        .bind_addr("127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap())
        .unwrap()
        .bind()
        .await
        .unwrap()
}
fn address(endpoint: &Endpoint) -> EndpointAddr {
    let mut address = EndpointAddr::new(endpoint.id());
    for ip in endpoint.addr().ip_addrs() {
        address = address.with_ip_addr(*ip);
    }
    assert!(address.ip_addrs().next().is_some());
    address
}
fn vector(name: &str) -> Vec<u8> {
    let source = include_str!("../../../../vectors/direct-room-v1.txt");
    let raw = source
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{name}=")))
        .unwrap();
    raw.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}
struct Data {
    genesis: PinnedGenesis,
    target: Checkpoint,
    frames: Vec<ReplicaFrame>,
}
impl Data {
    fn new(source: [u8; 32]) -> Self {
        let pin = RoomId::from_bytes(vector("genesis_id").try_into().unwrap());
        let genesis = SignedGenesis::decode(&vector("genesis_signed"))
            .unwrap()
            .verify_pin(pin)
            .unwrap();
        let frames = vec![
            ReplicaFrame {
                kind: FrameKind::Genesis,
                bytes: genesis.encode(),
            },
            ReplicaFrame {
                kind: FrameKind::Event,
                bytes: vector("event_signed"),
            },
            ReplicaFrame {
                kind: FrameKind::Policy,
                bytes: vector("policy_signed"),
            },
        ];
        let mut accumulator = SourceAccumulator::new(source, genesis.clone(), [9; 32]).unwrap();
        for frame in &frames {
            accumulator.push(frame.as_frame()).unwrap();
        }
        Self {
            genesis,
            target: accumulator.checkpoint().unwrap(),
            frames,
        }
    }
}
struct Custody(Arc<AtomicBool>);
impl Drop for Custody {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}
#[derive(Clone)]
struct Mock {
    data: Arc<Data>,
    seen: Arc<Mutex<Vec<[u8; 32]>>>,
    started: Arc<Semaphore>,
    pending: bool,
    wrong_source: bool,
    custody: Option<Arc<Custody>>,
}
impl Mock {
    fn new(source: [u8; 32]) -> Self {
        Self {
            data: Arc::new(Data::new(source)),
            seen: Arc::default(),
            started: Arc::new(Semaphore::new(0)),
            pending: false,
            wrong_source: false,
            custody: None,
        }
    }
}
impl Handler for Mock {
    async fn handle(&self, peer: [u8; 32], request: Request) -> Result<Reply> {
        self.seen.lock().unwrap().push(peer);
        self.started.add_permits(1);
        let _custody = &self.custody;
        if self.pending {
            std::future::pending::<()>().await;
        }
        match request {
            Request::Genesis { .. } => Ok(Reply::Genesis(self.data.genesis.encode())),
            Request::Head { .. } => Ok(Reply::Head(if self.wrong_source {
                Checkpoint {
                    source: [6; 32],
                    ..self.data.target
                }
            } else {
                self.data.target
            })),
            Request::Page {
                checkpoint,
                after,
                limit,
                ..
            } => {
                if checkpoint != self.data.target {
                    return Err(PeerError::Scope);
                }
                if after == checkpoint.records {
                    return Ok(Reply::Page(None));
                }
                let last = (after + limit as u64).min(checkpoint.records);
                Ok(Reply::Page(Some(ReplicaPage {
                    checkpoint,
                    first: after + 1,
                    last,
                    frames: self.data.frames[after as usize..last as usize].to_vec(),
                })))
            }
        }
    }
}
struct Host {
    endpoint: Endpoint,
    address: EndpointAddr,
    stop: watch::Sender<bool>,
    task: tokio::task::JoinHandle<Result<()>>,
}
impl Host {
    fn start(endpoint: Endpoint, handler: Mock, deadlines: Deadlines) -> Self {
        let address = address(&endpoint);
        let (stop, rx) = watch::channel(false);
        let owned = endpoint.clone();
        let task = tokio::spawn(serve_with(owned, handler, rx, deadlines));
        Self {
            endpoint,
            address,
            stop,
            task,
        }
    }
    async fn stop(self) {
        self.stop.send(true).unwrap();
        timeout(Duration::from_secs(5), self.task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(self.endpoint.is_closed());
    }
}
async fn raw_call(
    endpoint: &Endpoint,
    address: EndpointAddr,
    bytes: &[u8],
) -> std::result::Result<Vec<u8>, ()> {
    let connection = CloseConnection(endpoint.connect(address, ALPN).await.map_err(|_| ())?);
    let (mut send, mut recv) = connection.0.open_bi().await.map_err(|_| ())?;
    let _ = send.write_all(bytes).await;
    let _ = send.finish();
    recv.read_to_end(MAX_RESPONSE_BYTES).await.map_err(|_| ())
}

#[test]
fn loopback_head_pages_and_genesis_bind_the_real_peer_and_complete_sync() {
    run(async {
        let server = endpoint(true).await;
        let source = *server.id().as_bytes();
        let handler = Mock::new(source);
        let data = handler.data.clone();
        let seen = handler.seen.clone();
        let host = Host::start(server, handler, Deadlines::default());
        let peer = endpoint(false).await;
        let client = Client::default();
        let room = data.genesis.id();
        let observed = client
            .call_observed(&peer, host.address.clone(), Request::Genesis { room })
            .await
            .unwrap();
        let direct = PathSnapshot {
            selected: SelectedPath::Direct,
            nonempty: true,
            all_relay: false,
        };
        assert_eq!(observed.observation.before, direct);
        assert_eq!(observed.observation.after, direct);
        let genesis = observed.response;
        assert_eq!(genesis.source, source);
        assert_eq!(genesis.reply, Reply::Genesis(data.genesis.encode()));
        let head = client
            .call(&peer, host.address.clone(), Request::Head { room })
            .await
            .unwrap();
        assert_eq!(head.source, source);
        assert_eq!(head.reply, Reply::Head(data.target));
        let mut receiver =
            Receiver::begin(data.genesis.clone(), source, head.source, data.target).unwrap();
        for after in [0, 2] {
            let response = client
                .call(
                    &peer,
                    host.address.clone(),
                    Request::Page {
                        room,
                        checkpoint: data.target,
                        after,
                        limit: 2,
                    },
                )
                .await
                .unwrap();
            let Reply::Page(Some(page)) = response.reply else {
                panic!("expected fixed checkpoint page")
            };
            let frames: Vec<_> = page.frames.iter().map(ReplicaFrame::as_frame).collect();
            let prepared = receiver
                .prepare_page(Page {
                    checkpoint_id: page.checkpoint.id(),
                    first: page.first,
                    last: page.last,
                    frames: &frames,
                })
                .unwrap();
            receiver.commit_after_persist(prepared).unwrap();
        }
        assert_eq!(receiver.coverage(), Coverage::Complete);
        let end = client
            .call(
                &peer,
                host.address.clone(),
                Request::Page {
                    room,
                    checkpoint: data.target,
                    after: 3,
                    limit: 2,
                },
            )
            .await
            .unwrap();
        assert_eq!(end.reply, Reply::Page(None));
        assert_eq!(seen.lock().unwrap().as_slice(), &[*peer.id().as_bytes(); 5]);
        assert!(
            !peer.is_closed(),
            "calls do not close the caller-owned endpoint"
        );
        peer.close().await;
        host.stop().await;
    });
}

#[test]
fn path_snapshots_do_not_infer_missing_or_ambiguous_selections() {
    type Case<'a> = (&'a [(bool, bool, bool)], SelectedPath, bool, bool);
    let cases: &[Case<'_>] = &[
        (&[], SelectedPath::Unknown, false, false),
        (&[(true, true, false)], SelectedPath::Direct, true, false),
        (&[(true, false, true)], SelectedPath::Relay, true, true),
        (&[(false, false, true)], SelectedPath::Unknown, true, true),
        (
            &[(true, true, false), (false, false, true)],
            SelectedPath::Direct,
            true,
            false,
        ),
        (
            &[(false, true, false), (true, false, true)],
            SelectedPath::Relay,
            true,
            false,
        ),
        (
            &[(true, true, false), (true, false, true)],
            SelectedPath::Unknown,
            true,
            false,
        ),
        (&[(true, true, true)], SelectedPath::Unknown, true, false),
        (&[(true, false, false)], SelectedPath::Unknown, true, false),
    ];
    for (flags, selected, nonempty, all_relay) in cases {
        assert_eq!(
            PathSnapshot::from_flags(flags.iter().copied()),
            PathSnapshot {
                selected: *selected,
                nonempty: *nonempty,
                all_relay: *all_relay,
            }
        );
    }
    let snapshot = PathSnapshot::from_flags([(true, false, true)].into_iter());
    let observation = serde_json::to_value(PathObservation {
        before: snapshot,
        after: snapshot,
    })
    .unwrap();
    let expected = serde_json::json!({"selected": "relay", "nonempty": true, "all_relay": true});
    assert_eq!(
        observation,
        serde_json::json!({"before": expected, "after": expected})
    );
}

#[test]
fn wrong_source_checkpoint_and_wrong_authenticated_endpoint_never_succeed() {
    run(async {
        let server = endpoint(true).await;
        let mut handler = Mock::new(*server.id().as_bytes());
        handler.wrong_source = true;
        let room = handler.data.genesis.id();
        let host = Host::start(server, handler, Deadlines::default());
        let peer = endpoint(false).await;
        let client = Client::default();
        assert_eq!(
            client
                .call(&peer, host.address.clone(), Request::Head { room })
                .await,
            Err(PeerError::Scope)
        );
        let mut wrong = EndpointAddr::new(SecretKey::from_bytes(&[3; 32]).public());
        for ip in host.address.ip_addrs() {
            wrong = wrong.with_ip_addr(*ip);
        }
        assert!(client
            .call(&peer, wrong, Request::Head { room })
            .await
            .is_err());
        peer.close().await;
        host.stop().await;
    });
}

#[test]
fn malformed_oversized_truncated_and_write_verbs_never_reach_handler() {
    run(async {
        let server = endpoint(true).await;
        let handler = Mock::new(*server.id().as_bytes());
        let seen = handler.seen.clone();
        let room = handler.data.genesis.id();
        let host = Host::start(server, handler, Deadlines::default());
        let peer = endpoint(false).await;
        let head = encode_request(&Request::Head { room }).unwrap();
        let mut inputs = vec![
            vec![],
            vec![0; MAX_REQUEST_BYTES + 1],
            head[..head.len() - 1].to_vec(),
            br#"{"method":"append","text":"untrusted path"}"#.to_vec(),
        ];
        let mut trailing = head.clone();
        trailing.push(0);
        inputs.push(trailing);
        for verb in [0, 4, 5, 6, 7, 255] {
            let mut raw = head.clone();
            raw[8] = verb;
            inputs.push(raw);
        }
        for raw in inputs {
            let result = timeout(
                Duration::from_secs(3),
                raw_call(&peer, host.address.clone(), &raw),
            )
            .await
            .unwrap();
            assert!(result.is_err() || result.is_ok_and(|bytes| bytes.is_empty()));
        }
        assert!(seen.lock().unwrap().is_empty());
        let client = Client::default();
        assert!(client
            .call(&peer, host.address.clone(), Request::Head { room })
            .await
            .is_ok());
        peer.close().await;
        host.stop().await;
    });
}

#[test]
fn request_validation_rejects_bad_limits_scope_and_ranges_before_networking() {
    run(async {
        let server = endpoint(true).await;
        let handler = Mock::new(*server.id().as_bytes());
        let target = handler.data.target;
        let seen = handler.seen.clone();
        let host = Host::start(server, handler, Deadlines::default());
        let peer = endpoint(false).await;
        let client = Client::default();
        for (checkpoint, after, limit, error) in [
            (target, 0, 0, PeerError::Bounds),
            (target, 0, MAX_PAGE_FRAMES + 1, PeerError::Bounds),
            (target, target.records + 1, 1, PeerError::Bounds),
            (
                Checkpoint {
                    source: [2; 32],
                    ..target
                },
                0,
                1,
                PeerError::Scope,
            ),
            (
                Checkpoint {
                    epoch: [0; 32],
                    ..target
                },
                0,
                1,
                PeerError::Scope,
            ),
        ] {
            assert_eq!(
                client
                    .call(
                        &peer,
                        host.address.clone(),
                        Request::Page {
                            room: target.room,
                            checkpoint,
                            after,
                            limit
                        }
                    )
                    .await,
                Err(error)
            );
        }
        assert!(seen.lock().unwrap().is_empty());
        peer.close().await;
        host.stop().await;
    });
}

#[test]
fn request_trickle_has_one_absolute_frame_deadline() {
    run(async {
        let server = endpoint(true).await;
        let handler = Mock::new(*server.id().as_bytes());
        let room = handler.data.genesis.id();
        let seen = handler.seen.clone();
        let deadlines = Deadlines {
            frame: Duration::from_millis(250),
            backend: Duration::from_secs(1),
        };
        let host = Host::start(server, handler, deadlines);
        let peer = endpoint(false).await;
        let connection = CloseConnection(peer.connect(host.address.clone(), ALPN).await.unwrap());
        let (mut send, mut recv) = connection.0.open_bi().await.unwrap();
        let started = Instant::now();
        let raw = encode_request(&Request::Head { room }).unwrap();
        timeout(Duration::from_secs(1), async {
            for byte in raw {
                if send.write_all(&[byte]).await.is_err() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(60)).await;
            }
            let _ = send.finish();
            let result = recv.read_to_end(MAX_RESPONSE_BYTES).await;
            assert!(result.is_err() || result.is_ok_and(|bytes| bytes.is_empty()));
        })
        .await
        .unwrap();
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(seen.lock().unwrap().is_empty());
        drop(connection);
        peer.close().await;
        host.stop().await;
    });
}

#[test]
fn response_trickle_is_bounded_after_first_byte_and_never_yields_a_reply() {
    run(async {
        let server = endpoint(true).await;
        let address = address(&server);
        let source = *server.id().as_bytes();
        let room = Data::new(source).genesis.id();
        let owned = server.clone();
        let task = tokio::spawn(async move {
            let connection = CloseConnection(owned.accept().await.unwrap().await.unwrap());
            let (mut send, mut recv) = connection.0.accept_bi().await.unwrap();
            recv.read_to_end(MAX_REQUEST_BYTES).await.unwrap();
            for byte in RESPONSE_MAGIC {
                if send.write_all(&[*byte]).await.is_err() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(60)).await;
            }
            let _ = send.finish();
        });
        let peer = endpoint(false).await;
        let client = Client {
            deadlines: Deadlines {
                frame: Duration::from_millis(250),
                backend: Duration::from_secs(1),
            },
            ..Client::default()
        };
        let result = client.call(&peer, address, Request::Head { room }).await;
        peer.close().await;
        timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap();
        server.close().await;
        assert_eq!(result, Err(PeerError::Timeout));
    });
}

#[test]
fn caps_are_independent_and_shutdown_joins_pending_workers_before_custody_release() {
    run(async {
        let server = endpoint(true).await;
        let mut handler = Mock::new(*server.id().as_bytes());
        handler.pending = true;
        let room = handler.data.genesis.id();
        let started = handler.started.clone();
        let dropped = Arc::new(AtomicBool::new(false));
        let custody = Arc::new(Custody(dropped.clone()));
        let weak = Arc::downgrade(&custody);
        handler.custody = Some(custody);
        let host = Host::start(server, handler, Deadlines::default());
        let peer = endpoint(false).await;
        let client = Client::default();
        let mut calls = JoinSet::new();
        for _ in 0..MAX_CLIENT_CALLS {
            let (peer, client, address) = (peer.clone(), client.clone(), host.address.clone());
            calls.spawn(async move { client.call(&peer, address, Request::Head { room }).await });
        }
        timeout(
            Duration::from_secs(5),
            started.acquire_many(MAX_CLIENT_CALLS as u32),
        )
        .await
        .unwrap()
        .unwrap()
        .forget();
        assert!(weak.upgrade().is_some());
        assert!(!dropped.load(Ordering::Acquire));
        assert_eq!(
            client
                .call(&peer, host.address.clone(), Request::Head { room })
                .await,
            Err(PeerError::Capacity)
        );
        // A raw dial bypasses the client permit pool and still meets the server cap.
        let refused = timeout(
            Duration::from_secs(3),
            peer.connect(host.address.clone(), ALPN),
        )
        .await;
        assert!(refused.is_err() || refused.is_ok_and(|result| result.is_err()));
        host.stop().await;
        assert!(weak.upgrade().is_none());
        assert!(dropped.load(Ordering::Acquire));
        while let Some(result) = calls.join_next().await {
            assert!(result.unwrap().is_err());
        }
        assert_eq!(client.permits.available_permits(), MAX_CLIENT_CALLS);
        peer.close().await;
    });
}

#[test]
fn pending_backend_has_a_fixed_deadline_and_returns_only_static_error() {
    run(async {
        let server = endpoint(true).await;
        let mut handler = Mock::new(*server.id().as_bytes());
        handler.pending = true;
        let room = handler.data.genesis.id();
        let deadlines = Deadlines {
            frame: Duration::from_secs(2),
            backend: Duration::from_millis(100),
        };
        let host = Host::start(server, handler, deadlines);
        let peer = endpoint(false).await;
        let result = Client::default()
            .call(&peer, host.address.clone(), Request::Head { room })
            .await;
        peer.close().await;
        host.stop().await;
        assert_eq!(result, Err(PeerError::Timeout));
    });
}

#[test]
fn codec_checks_reply_shape_bounds_and_exact_frozen_page() {
    let data = Data::new([7; 32]);
    let request = Request::Page {
        room: data.target.room,
        checkpoint: data.target,
        after: 0,
        limit: 2,
    };
    let page = ReplicaPage {
        checkpoint: data.target,
        first: 1,
        last: 2,
        frames: data.frames[..2].to_vec(),
    };
    let valid = Reply::Page(Some(page.clone()));
    let encoded = encode_reply(Ok(valid.clone())).unwrap();
    assert_eq!(decode_reply(&encoded).unwrap(), valid);
    check_reply(&request, &valid, data.target.source).unwrap();
    for bad in [
        ReplicaPage {
            first: 2,
            ..page.clone()
        },
        ReplicaPage {
            last: 3,
            ..page.clone()
        },
        ReplicaPage {
            frames: data.frames[..1].to_vec(),
            ..page.clone()
        },
        ReplicaPage {
            checkpoint: Checkpoint {
                digest: [4; 32],
                ..data.target
            },
            ..page.clone()
        },
        ReplicaPage {
            frames: vec![data.frames[0].clone(); MAX_PAGE_FRAMES + 1],
            ..page.clone()
        },
    ] {
        assert!(check_reply(&request, &Reply::Page(Some(bad)), data.target.source).is_err());
    }
    assert!(check_reply(&request, &Reply::Page(None), data.target.source).is_err());
    let mut oversized = page.clone();
    oversized.frames[1].bytes = vec![0; MAX_EVENT_BYTES + 1];
    assert_eq!(
        encode_reply(Ok(Reply::Page(Some(oversized)))),
        Err(PeerError::Bounds)
    );
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert_eq!(decode_reply(&trailing), Err(PeerError::Malformed));
    for end in 0..encoded.len() {
        assert!(decode_reply(&encoded[..end]).is_err());
    }
    assert_eq!(
        decode_reply(&vec![0; MAX_RESPONSE_BYTES + 1]),
        Err(PeerError::Bounds)
    );
}
