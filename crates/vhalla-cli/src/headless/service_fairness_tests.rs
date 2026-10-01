//! Real private delivery progresses through the actor while both queues are busy.
//!
//! Registered below service_private_tests to reuse its native/TLS fixtures.
use super::*;
use crate::headless::{network, peer};
use tokio::sync::{oneshot, watch};

#[derive(Clone, Copy, Default)]
struct Progress {
    ticks: usize,
    local: usize,
    peer: usize,
}

/// Observe completed work without changing admission, cadence or native results.
struct Observed {
    service: ServiceBackend,
    progress: Progress,
    ticks: watch::Sender<Progress>,
    ready: Option<oneshot::Sender<()>>,
}
impl local::Backend for Observed {
    async fn dispatch(&mut self, channel: Channel, request: Value) -> Result<Reply> {
        let result = Box::pin(self.service.dispatch(channel, request)).await;
        self.progress.local += 1;
        result
    }
    async fn tick(&mut self) -> Result<()> {
        Box::pin(self.service.tick()).await?;
        self.progress.ticks += 1;
        self.ticks.send_replace(self.progress);
        if let Some(ready) = self.ready.take() {
            let _ = ready.send(());
        }
        Ok(())
    }
    async fn peer(
        &mut self,
        identity: [u8; 32],
        request: peer::Request,
    ) -> std::result::Result<peer::Reply, peer::PeerError> {
        let result = self.service.peer(identity, request).await;
        self.progress.peer += 1;
        result
    }
    fn invalidate(&mut self) {
        self.service.invalidate();
    }
}

/// Join auxiliary native work before the fixture can delete its files, including
/// when the receiver journey times out or an assertion unwinds.
struct SenderWorker(Option<thread::JoinHandle<()>>);
impl Drop for SenderWorker {
    fn drop(&mut self) {
        if let Some(worker) = self.0.take() {
            let result = worker.join();
            if !thread::panicking() {
                result.expect("sender runtime completed");
            }
        }
    }
}

async fn pair(owner: &mut ServiceBackend, member: &mut ServiceBackend, base: u8) -> (Value, Value) {
    let time = now();
    let valid = json!({"not_before":time-1,"expires_at":time+3600});
    let initial = admin(
        owner,
        json!({"op":"room.create","operation":id(base),
        "kind":"private","limits":limits(),"validity":valid}),
    )
    .await;
    let recipient = admin(member, json!({"op":"service.status"})).await["account"].clone();
    let offer = admin(
        owner,
        json!({"op":"private.offer","room":id(base),
        "operation":id(base+1),"recipient":recipient,"validity":valid}),
    )
    .await;
    let joined = admin(
        member,
        json!({"op":"room.join_private","operation":id(base+2),
        "offer":offer["offer"],"expected_owner":initial["context"]["account"],
        "validity":valid,"limits":limits()}),
    )
    .await;
    let admitted = admin(
        owner,
        json!({"op":"private.accept_contact","room":id(base),
        "operation":id(base+3),"request":joined["request"],"validity":valid}),
    )
    .await;
    let member_status = admin(
        member,
        json!({"op":"private.join_contact","room":id(base+2),
        "response":admitted["artifact"]}),
    )
    .await;
    let owner_status = admin(owner, json!({"op":"room.status","room":id(base)})).await;
    assert_eq!(owner_status["roster"], member_status["roster"]);
    (owner_status, member_status)
}

async fn call(home: &Path, request: Value) -> Value {
    let operation = request["op"].clone();
    local::admin_request(home, request)
        .await
        .unwrap_or_else(|error| panic!("local {operation}: {error:?}"))
}

// Match headless::run: private TLS exchanges are synchronous and must not
// prevent the independent Iroh I/O tasks from meeting their frame deadlines.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_private_rooms_progress_under_sustained_local_and_public_peer_demand() {
    // Each independent room needs its own mailbox: unrelated encrypted owner
    // controls at the same sequence are conflicting history, not local echoes.
    let environments = [Environment::new(), Environment::new()];
    // Keep the Unix socket path within the platform limit.
    let short = tempfile::Builder::new()
        .prefix("vh-fair-")
        .tempdir_in(if cfg!(target_os = "macos") {
            "/private/tmp"
        } else {
            "/tmp"
        })
        .unwrap();
    let home = short.path().join("hub");
    let mut hub = initialized(&home, 101).await;
    let mut sender = initialized(&environments[0].base.join("sender"), 102).await;
    let (first_owner, first_member) = pair(&mut sender, &mut hub, 1).await;
    let (second_owner, second_member) = pair(&mut sender, &mut hub, 11).await;
    let owner_profiles = [
        environments[0].profile("first-owner", &first_owner),
        environments[1].profile("second-owner", &second_owner),
    ];
    let member_profiles = [
        environments[0].profile("first-member", &first_member),
        environments[1].profile("second-member", &second_member),
    ];
    install(&mut sender, id(1), 40, &owner_profiles[0]).await;
    install(&mut sender, id(11), 41, &owner_profiles[1]).await;
    let public = create(&mut hub, 21, false).await;
    admin(
        &mut hub,
        json!({"op":"public.publish","room":id(21),"operation":id(22)}),
    )
    .await;
    let pin: Hash = serde_json::from_value(public["pin"].clone()).unwrap();
    let public_room = vhalla_direct_room::RoomId::from_bytes(pin.0);
    drop(hub);

    let (ticks, mut observed_ticks) = watch::channel(Progress::default());
    let (ready, started) = oneshot::channel();
    let (address, selected_address) = oneshot::channel();
    let server_home = &home;
    let server = local::serve_factory(
        &home,
        |generation| async move {
            let mut service = Box::pin(ServiceBackend::open(server_home, generation)).await?;
            let endpoint = service
                .bind_network(&network::Listen {
                    bind: "127.0.0.1:0".parse().unwrap(),
                    relay_url: None,
                    relay_only: false,
                })
                .await?;
            let _ = address.send(endpoint.addr());
            Ok(local::Launch {
                backend: Observed {
                    service,
                    progress: Progress::default(),
                    ticks,
                    ready: Some(ready),
                },
                endpoint: Some(endpoint),
            })
        },
        std::future::pending(),
    );
    let journey = async {
        // A completed real maintenance step proves both local listeners exist.
        started.await.unwrap();
        let destination = selected_address.await.unwrap();
        let endpoint = peer::endpoint_builder()
            .bind_addr("127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap())
            .unwrap()
            .bind()
            .await
            .unwrap();
        let client = peer::Client::default();
        let (stop, stopping) = watch::channel(false);
        let local_stop = stopping.clone();
        let peer_stop = stopping;
        let (local_entered, local_started) = oneshot::channel();
        let (peer_entered, peer_started) = oneshot::channel();
        let public_seen = AtomicBool::new(false);
        let local_demand = async {
            let mut entered = Some(local_entered);
            let mut completed = 0usize;
            // Exactly one outstanding request per demand producer. The cap
            // bounds pathological timer starvation without saturating admission.
            while !*local_stop.borrow() {
                assert!(completed < 8192, "maintenance starved under local demand");
                let status = call(&home, json!({"op":"service.status"})).await;
                assert!(status["account"].is_string());
                completed += 1;
                if let Some(entered) = entered.take() {
                    let _ = entered.send(());
                }
            }
            completed
        };
        let peer_demand = async {
            let mut entered = Some(peer_entered);
            let mut completed = 0usize;
            let mut saw_public = false;
            while !*peer_stop.borrow() {
                assert!(completed < 8192, "maintenance starved under public demand");
                let head = client
                    .call(
                        &endpoint,
                        destination.clone(),
                        peer::Request::Head { room: public_room },
                    )
                    .await
                    .unwrap_or_else(|error| {
                        panic!("public head after {completed} completed reads: {error:?}")
                    });
                let peer::Reply::Head(checkpoint) = head.reply else {
                    panic!("public head")
                };
                let page = client
                    .call(
                        &endpoint,
                        destination.clone(),
                        peer::Request::Page {
                            room: public_room,
                            checkpoint,
                            after: 0,
                            limit: 8,
                        },
                    )
                    .await
                    .unwrap_or_else(|error| {
                        panic!("public page after {completed} completed reads: {error:?}")
                    });
                if let peer::Reply::Page(Some(page)) = page.reply {
                    saw_public |= page.frames.iter().any(|frame| {
                        frame
                            .bytes
                            .windows(b"public under mixed traffic".len())
                            .any(|bytes| bytes == b"public under mixed traffic")
                    });
                    public_seen.store(saw_public, Ordering::SeqCst);
                }
                completed += 1;
                if let Some(entered) = entered.take() {
                    let _ = entered.send(());
                }
            }
            (completed, saw_public)
        };
        let controller = async {
            local_started.await.unwrap();
            peer_started.await.unwrap();
            for (room, operation, profile) in [
                (id(3), 50, &member_profiles[0]),
                (id(13), 51, &member_profiles[1]),
            ] {
                assert_eq!(call(&home, setup(room, profile)).await["initialized"], true);
                assert_eq!(
                    call(&home, attach(room, operation, profile)).await["current"]["state"],
                    "active"
                );
            }
            let first_request = send(&first_owner, 60, "first private under demand");
            let second_request = send(&second_owner, 61, "second private under demand");
            let (published, publication) = oneshot::channel();
            // Another daemon has its own runtime. Its synchronous TLS work
            // must not block this task's receiver actor or demand producers.
            let sender_worker = SenderWorker(Some(thread::spawn(move || {
                tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(2)
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(async {
                        let first = admin(&mut sender, first_request).await;
                        let second = admin(&mut sender, second_request).await;
                        // Two explicit sender rounds publish both native
                        // outboxes. The receiver uses only actor maintenance.
                        for _ in 0..4 {
                            tick(&mut sender).await;
                        }
                        for (room, sent) in [(id(1), &first), (id(11), &second)] {
                            let status = delivery(&mut sender, room).await;
                            assert_eq!(status["state"], "active", "sender delivery: {status}");
                            assert!(
                                status["application"]["records"]
                                    .as_array()
                                    .unwrap_or_else(|| {
                                        panic!("sender application records missing: {status}")
                                    })
                                    .iter()
                                    .any(|row| row["sequence"] == sent["sequence"]
                                        && row["state"] == "retained"),
                                "{status}"
                            );
                        }
                    });
                let _ = published.send(());
            })));
            publication.await.expect("sender published both rooms");
            drop(sender_worker);
            call(
                &home,
                json!({"op":"room.send","room":id(21),"operation":id(62),
                "body":"public under mixed traffic"}),
            )
            .await;
            let baseline = *observed_ticks.borrow_and_update();
            let mut received = [false; 2];
            // The existing quiet mailbox cadence is five seconds; 24 actual
            // maintenance ticks allow that interval and both room turns.
            loop {
                observed_ticks.changed().await.unwrap();
                let progress = *observed_ticks.borrow_and_update();
                assert!(
                    progress.ticks <= baseline.ticks + 24,
                    "private maintenance did not converge"
                );
                for (index, room, body, owner) in [
                    (0, id(3), "first private under demand", &first_owner),
                    (1, id(13), "second private under demand", &second_owner),
                ] {
                    let page = call(
                        &home,
                        json!({"op":"room.messages","room":room,"after":0,"limit":16}),
                    )
                    .await;
                    let count = message_count(&page, body, &owner["context"]["device"]);
                    assert!(count <= 1);
                    received[index] |= count == 1;
                    let state = call(
                        &home,
                        json!({"op":"private.delivery_status","room":room,"after":0,"limit":16}),
                    )
                    .await;
                    assert_eq!(state["state"], "active", "receiver delivery: {state}");
                }
                if received == [true, true]
                    && progress.local > baseline.local
                    && progress.peer > baseline.peer
                    && public_seen.load(Ordering::SeqCst)
                {
                    break;
                }
            }
            stop.send_replace(true);
        };
        let (local_calls, (peer_reads, saw_public), ()) = tokio::join!(
            Box::pin(local_demand),
            Box::pin(peer_demand),
            Box::pin(controller)
        );
        assert!(local_calls > 1 && peer_reads > 1);
        assert!(saw_public, "public snapshot maintenance was starved");
        endpoint.close().await;
        call(&home, json!({"op":"control.stop"})).await;
    };
    let (served, ()) = tokio::time::timeout(Duration::from_secs(20), async {
        tokio::join!(Box::pin(server), Box::pin(journey))
    })
    .await
    .expect("composed actor fairness completed within its wall-time bound");
    served.unwrap();
    assert!(!home.join("control/admin.sock").exists());
    assert!(!home.join("control/agent.sock").exists());
}
