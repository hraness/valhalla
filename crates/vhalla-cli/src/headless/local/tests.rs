use super::*;
use std::{
    fs,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Mutex,
    },
};
use tokio::io::AsyncReadExt;

static NEXT: AtomicU64 = AtomicU64::new(0);

pub(super) struct Temp(pub(super) PathBuf);
impl Temp {
    pub(super) fn new() -> Self {
        let path = PathBuf::from("/private/tmp").join(format!(
            "vh-ipc-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        #[cfg(not(target_os = "macos"))]
        let path = PathBuf::from("/tmp").join(path.file_name().unwrap());
        vhalla_custody::create_private_directory(&path).unwrap();
        Self(path)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

struct BackendProbe {
    home: PathBuf,
    channels: Arc<Mutex<Vec<Channel>>>,
    entered: Option<oneshot::Sender<()>>,
    release: Option<oneshot::Receiver<()>>,
    finished: Arc<AtomicBool>,
    dropped_under_lock: Arc<AtomicBool>,
}

impl BackendProbe {
    fn new(home: &Path) -> Self {
        Self {
            home: home.into(),
            channels: Arc::new(Mutex::new(Vec::new())),
            entered: None,
            release: None,
            finished: Arc::new(AtomicBool::new(false)),
            dropped_under_lock: Arc::new(AtomicBool::new(false)),
        }
    }
}
impl Backend for BackendProbe {
    async fn dispatch(&mut self, channel: Channel, request: Value) -> Result<Reply, ErrorBody> {
        self.channels.lock().unwrap().push(channel);
        match request.get("op").and_then(Value::as_str) {
            Some("wait") => {
                self.entered.take().unwrap().send(()).unwrap();
                let _ = self.release.take().unwrap().await;
                self.finished.store(true, Ordering::SeqCst);
            }
            Some("large-error") => {
                return Err(ErrorBody::new(
                    ErrorCode::Internal,
                    "x".repeat(MAX_RESPONSE_BYTES + 1),
                ))
            }
            Some("large-result") => {
                return Ok(Reply::unrestricted(json!(
                    "x".repeat(MAX_RESPONSE_BYTES + 1)
                )))
            }
            _ => {}
        }
        Ok(Reply::unrestricted(
            json!({"channel": if channel == Channel::Admin { "admin" } else { "agent" }, "request": request}),
        ))
    }
}
impl Drop for BackendProbe {
    fn drop(&mut self) {
        self.dropped_under_lock.store(
            matches!(Guard::acquire(&self.home), Err(error) if error.code == ErrorCode::ControlAlreadyRunning),
            Ordering::SeqCst,
        );
    }
}

pub(super) async fn ready(home: &Path) {
    timeout(Duration::from_secs(5), async {
        loop {
            if admin_request(home, json!({"op":"control.hello"}))
                .await
                .is_ok()
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("service became ready");
}

fn output_frontend(home: &Path) -> Frontend {
    let (queue, _) = mpsc::channel(1);
    let (stop, _) = watch::channel(false);
    Frontend {
        queue,
        stop,
        admin_clients: Arc::new(Semaphore::new(1)),
        agent_clients: Arc::new(Semaphore::new(1)),
        guard: Arc::new(Guard::acquire(home).unwrap()),
        deadlines: Deadlines::default(),
        output: Arc::new(RwLock::new(())),
    }
}

#[tokio::test]
async fn revoked_output_permits_hide_prepared_content_before_transport_release() {
    let temp = Temp::new();
    let frontend = output_frontend(&temp.0);
    let valid = Arc::new(AtomicBool::new(true));
    let checker = Arc::clone(&valid);
    let reply = Reply::guarded(
        json!({"body":"confidential sentinel"}),
        OutputPermit::new(move || checker.load(Ordering::SeqCst)),
    );
    assert_eq!(
        reply.checked_value().unwrap()["body"],
        "confidential sentinel"
    );
    valid.store(false, Ordering::SeqCst);
    assert_eq!(
        reply.check_release().unwrap_err().code,
        ErrorCode::PermissionDenied
    );
    let (mut writer, reader) = tokio::io::duplex(4096);
    write_response(
        &mut writer,
        Ok(reply),
        &frontend,
        &mut frontend.stop.subscribe(),
    )
    .await
    .unwrap();
    let frame = read_frame(&mut BufReader::new(reader), MAX_RESPONSE_BYTES)
        .await
        .unwrap()
        .unwrap();
    assert!(!String::from_utf8_lossy(&frame).contains("confidential sentinel"));
    let value: Value = serde_json::from_slice(&frame).unwrap();
    assert_eq!(value["ok"], false);
    assert_eq!(
        value["error"]["code"],
        serde_json::to_value(ErrorCode::PermissionDenied).unwrap()
    );
}

#[tokio::test]
async fn prepared_output_waits_for_mutation_and_its_final_audit() {
    let temp = Temp::new();
    let frontend = output_frontend(&temp.0);
    let mutation = frontend.output.write().await;
    let live = Arc::new(AtomicBool::new(true));
    let checker = Arc::clone(&live);
    let reply = Reply::guarded(
        json!({"secret":"before removal"}),
        OutputPermit::new(move || checker.load(Ordering::SeqCst)),
    );
    let (mut writer, mut reader) = tokio::io::duplex(4096);
    let release = async {
        write_response(
            &mut writer,
            Ok(reply),
            &frontend,
            &mut frontend.stop.subscribe(),
        )
        .await
        .unwrap();
    };
    let change_authority = async {
        assert!(timeout(Duration::from_millis(20), reader.read_u8())
            .await
            .is_err());
        live.store(false, Ordering::SeqCst);
        drop(mutation);
        let frame = read_frame(&mut BufReader::new(reader), MAX_RESPONSE_BYTES)
            .await
            .unwrap()
            .unwrap();
        assert!(!String::from_utf8_lossy(&frame).contains("before removal"));
        let value: Value = serde_json::from_slice(&frame).unwrap();
        assert_eq!(value["ok"], false);
    };
    tokio::join!(release, change_authority);
}

#[tokio::test]
async fn output_holds_authority_through_the_last_byte_but_has_a_fixed_deadline() {
    let temp = Temp::new();
    let mut frontend = output_frontend(&temp.0);
    let (mut writer, mut reader) = tokio::io::duplex(1);
    let reply = Reply::guarded(json!({"secret":"authorized"}), OutputPermit::new(|| true));
    let release = async {
        write_response(
            &mut writer,
            Ok(reply),
            &frontend,
            &mut frontend.stop.subscribe(),
        )
        .await
        .unwrap();
    };
    let drain = async {
        assert_eq!(reader.read_u8().await.unwrap(), b'{');
        assert!(frontend.output.try_write().is_err());
        assert!(read_frame(&mut BufReader::new(reader), MAX_RESPONSE_BYTES)
            .await
            .unwrap()
            .is_some());
    };
    tokio::join!(release, drain);
    drop(frontend.output.try_write().unwrap());

    frontend.deadlines.frame = Duration::from_millis(20);
    let (mut blocked, _reader) = tokio::io::duplex(1);
    let reply = Reply::guarded(json!({"secret":"authorized"}), OutputPermit::new(|| true));
    assert!(write_response(
        &mut blocked,
        Ok(reply),
        &frontend,
        &mut frontend.stop.subscribe()
    )
    .await
    .is_err());
    drop(frontend.output.try_write().unwrap());
}

#[tokio::test]
async fn output_expiry_while_blocked_prevents_any_write_on_resume() {
    let temp = Temp::new();
    let frontend = output_frontend(&temp.0);
    let clock = Arc::new(AtomicU64::new(41));
    let checker = Arc::clone(&clock);
    let reply = Reply::guarded(
        json!({"secret":"must never leave the blocked writer"}),
        OutputPermit::new(move || checker.load(Ordering::SeqCst) < 42),
    );
    let (mut writer, mut reader) = tokio::io::duplex(1);
    writer.write_all(b"x").await.unwrap();
    let mut stop = frontend.stop.subscribe();
    let mut release = Box::pin(write_response(&mut writer, Ok(reply), &frontend, &mut stop));
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    assert!(release.as_mut().poll(&mut cx).is_pending());
    assert!(frontend.output.try_write().is_err());

    // Advancing the controlled clock and freeing capacity does not poll the
    // response. Its next poll must refuse before touching the writable stream.
    clock.store(42, Ordering::SeqCst);
    assert_eq!(reader.read_u8().await.unwrap(), b'x');
    assert!(matches!(
        release.as_mut().poll(&mut cx),
        Poll::Ready(Err(()))
    ));
    drop(release);
    drop(writer);
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).await.unwrap();
    assert!(bytes.is_empty());
    drop(frontend.output.try_write().unwrap());
}

struct PartialWriter<F> {
    bytes: Vec<u8>,
    polls: usize,
    after_first: Option<F>,
}

impl<F: FnOnce() + Unpin> AsyncWrite for PartialWriter<F> {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.polls += 1;
        let count = if this.after_first.is_some() {
            bytes.len().min(7)
        } else {
            bytes.len()
        };
        this.bytes.extend_from_slice(&bytes[..count]);
        if let Some(change) = this.after_first.take() {
            change();
        }
        Poll::Ready(Ok(count))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut std::task::Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn partial_output_expiry_stops_progress_without_appending_an_error_frame() {
    let temp = Temp::new();
    let frontend = output_frontend(&temp.0);
    let clock = Arc::new(AtomicU64::new(41));
    let checker = Arc::clone(&clock);
    let value = json!({"secret":"only the authorized prefix may leave"});
    let expected = response(Ok(value.clone()));
    let reply = Reply::guarded(
        value,
        OutputPermit::new(move || checker.load(Ordering::SeqCst) < 42),
    );
    let mut writer = PartialWriter {
        bytes: Vec::new(),
        polls: 0,
        // Expire during a successful partial write without returning Pending.
        after_first: Some(|| clock.store(42, Ordering::SeqCst)),
    };
    assert!(write_response(
        &mut writer,
        Ok(reply),
        &frontend,
        &mut frontend.stop.subscribe(),
    )
    .await
    .is_err());
    assert_eq!(writer.polls, 1);
    assert_eq!(writer.bytes, expected[..7]);
    assert!(!writer.bytes.contains(&b'\n'));
    drop(frontend.output.try_write().unwrap());
}

#[tokio::test]
async fn partial_output_shared_custody_loss_stops_before_another_write_poll() {
    let temp = Temp::new();
    let frontend = output_frontend(&temp.0);
    let value = json!({"secret":"the changed service cannot finish this frame"});
    let expected = response(Ok(value.clone()));
    let mut writer = PartialWriter {
        bytes: Vec::new(),
        polls: 0,
        after_first: Some(|| fs::write(&frontend.guard.paths().cap, [b'x'; 64]).unwrap()),
    };
    assert!(write_response(
        &mut writer,
        Ok(Reply::guarded(value, OutputPermit::new(|| true))),
        &frontend,
        &mut frontend.stop.subscribe(),
    )
    .await
    .is_err());
    assert_eq!(writer.polls, 1);
    assert_eq!(writer.bytes, expected[..7]);
    drop(frontend.output.try_write().unwrap());
}

#[tokio::test]
async fn shutdown_refuses_output_waiting_for_a_mutation_without_waiting_for_the_actor() {
    let temp = Temp::new();
    let frontend = output_frontend(&temp.0);
    let _mutation = frontend.output.write().await;
    let (mut writer, mut reader) = tokio::io::duplex(4096);
    let reply = Reply::guarded(json!({"secret":"pending"}), OutputPermit::new(|| true));
    frontend.stop.send_replace(true);
    assert!(write_response(
        &mut writer,
        Ok(reply),
        &frontend,
        &mut frontend.stop.subscribe()
    )
    .await
    .is_err());
    drop(writer);
    assert_eq!(reader.read(&mut [0]).await.unwrap(), 0);
}

#[tokio::test]
async fn channels_are_socket_derived_and_only_authenticated_admin_can_stop() {
    let temp = Temp::new();
    let backend = BackendProbe::new(&temp.0);
    let channels = Arc::clone(&backend.channels);
    let dropped = Arc::clone(&backend.dropped_under_lock);
    let interaction = async {
        ready(&temp.0).await;
        let paths = custody::preflight(&temp.0).unwrap();
        let admin = admin_request(&temp.0, json!({"op":"echo"})).await.unwrap();
        assert_eq!(admin["channel"], "admin");
        let agent = agent_request(&temp.0, json!({"op":"echo", "channel":"admin"}))
            .await
            .unwrap();
        assert_eq!(agent["channel"], "agent");
        for frame in [
            json!({"v":1,"protocol":AGENT_PROTOCOL,"request":{"op":"control.stop"}}),
            json!({"v":1,"protocol":control::CONTROL_PROTOCOL,"request":{"op":"control.stop"}}),
            json!({"v":1,"protocol":AGENT_PROTOCOL,"cap":"wrong","request":{"op":"echo"}}),
        ] {
            assert_eq!(
                exchange(&paths.agent_sock, Channel::Agent, frame)
                    .await
                    .unwrap_err()
                    .code,
                ErrorCode::PermissionDenied
            );
        }
        assert_eq!(
            exchange(
                &paths.admin_sock,
                Channel::Admin,
                json!({"v":1,"cap":"wrong","request":{"op":"control.stop"}})
            )
            .await
            .unwrap_err()
            .code,
            ErrorCode::PermissionDenied
        );
        assert_eq!(
            admin_request(&temp.0, json!({"op":"control.stop"}))
                .await
                .unwrap()["stopping"],
            true
        );
    };
    let (result, ()) = timeout(Duration::from_secs(10), async {
        tokio::join!(serve(&temp.0, backend, std::future::pending()), interaction)
    })
    .await
    .unwrap();
    result.unwrap();
    assert_eq!(*channels.lock().unwrap(), [Channel::Admin, Channel::Agent]);
    assert!(dropped.load(Ordering::SeqCst));
    drop(Guard::acquire(&temp.0).unwrap());
}

#[tokio::test]
async fn stop_and_client_timeout_preserve_inflight_work_and_owner_custody() {
    let temp = Temp::new();
    let mut backend = BackendProbe::new(&temp.0);
    let (entered, entering) = oneshot::channel();
    let (release, releasing) = oneshot::channel();
    backend.entered = Some(entered);
    backend.release = Some(releasing);
    let finished = Arc::clone(&backend.finished);
    let dropped = Arc::clone(&backend.dropped_under_lock);
    let interaction = async {
        ready(&temp.0).await;
        let request = admin_request(&temp.0, json!({"op":"wait"}));
        let control = async {
            entering.await.unwrap();
            // Let the transport abandon its reply before stopping. Neither
            // timeout nor control.stop releases the backend's supervisor lock.
            tokio::time::sleep(Duration::from_millis(100)).await;
            let paths = custody::preflight(&temp.0).unwrap();
            let mut slow = UnixStream::connect(&paths.agent_sock).await.unwrap();
            slow.write_all(b"{").await.unwrap();
            admin_request(&temp.0, json!({"op":"control.stop"}))
                .await
                .unwrap();
            assert!(!finished.load(Ordering::SeqCst));
            assert!(
                matches!(Guard::acquire(&temp.0), Err(error) if error.code == ErrorCode::ControlAlreadyRunning)
            );
            assert_eq!(
                timeout(Duration::from_secs(1), slow.read(&mut [0; 8]))
                    .await
                    .unwrap()
                    .unwrap(),
                0
            );
            release.send(()).unwrap();
        };
        let (answer, ()) = tokio::join!(request, control);
        assert_eq!(answer.unwrap_err().code, ErrorCode::OwnerUnavailable);
    };
    let (result, ()) = timeout(Duration::from_secs(10), async {
        tokio::join!(
            serve_with_deadlines(
                &temp.0,
                backend,
                std::future::pending(),
                Deadlines {
                    frame: Duration::from_secs(2),
                    response: Duration::from_millis(40),
                }
            ),
            interaction
        )
    })
    .await
    .unwrap();
    result.unwrap();
    assert!(finished.load(Ordering::SeqCst));
    assert!(dropped.load(Ordering::SeqCst));
    drop(Guard::acquire(&temp.0).unwrap());
}

#[tokio::test]
async fn external_shutdown_does_not_cancel_an_accepted_operation() {
    let temp = Temp::new();
    let mut backend = BackendProbe::new(&temp.0);
    let (entered, entering) = oneshot::channel();
    let (release, releasing) = oneshot::channel();
    let (shutdown, shutting_down) = oneshot::channel();
    backend.entered = Some(entered);
    backend.release = Some(releasing);
    let finished = Arc::clone(&backend.finished);
    let interaction = async {
        ready(&temp.0).await;
        let request = admin_request(&temp.0, json!({"op":"wait"}));
        let stopping = async {
            entering.await.unwrap();
            shutdown.send(()).unwrap();
            tokio::task::yield_now().await;
            assert!(!finished.load(Ordering::SeqCst));
            assert!(
                matches!(Guard::acquire(&temp.0), Err(error) if error.code == ErrorCode::ControlAlreadyRunning)
            );
            release.send(()).unwrap();
        };
        let (_, ()) = tokio::join!(request, stopping);
    };
    let (result, ()) = timeout(Duration::from_secs(10), async {
        tokio::join!(
            serve(&temp.0, backend, async {
                let _ = shutting_down.await;
            }),
            interaction
        )
    })
    .await
    .unwrap();
    result.unwrap();
    assert!(finished.load(Ordering::SeqCst));
}

#[tokio::test]
async fn cancelling_service_drops_backend_before_transport_releases_lock() {
    let temp = Temp::new();
    let mut backend = BackendProbe::new(&temp.0);
    let (entered, entering) = oneshot::channel();
    let (_release, releasing) = oneshot::channel();
    backend.entered = Some(entered);
    backend.release = Some(releasing);
    let dropped = Arc::clone(&backend.dropped_under_lock);
    let finished = Arc::clone(&backend.finished);
    let mut service = Box::pin(serve(&temp.0, backend, std::future::pending()));
    let mut clients = JoinSet::new();
    let interaction = async {
        ready(&temp.0).await;
        let home = temp.0.clone();
        clients.spawn(async move { admin_request(&home, json!({"op":"wait"})).await });
        entering.await.unwrap();
    };
    timeout(Duration::from_secs(10), async {
        tokio::select! {
            result = &mut service => panic!("unexpected completion: {result:?}"),
            () = interaction => {},
        }
    })
    .await
    .unwrap();
    drop(service);
    assert!(!finished.load(Ordering::SeqCst));
    assert!(dropped.load(Ordering::SeqCst));
    timeout(Duration::from_secs(5), async {
        loop {
            match Guard::acquire(&temp.0) {
                Ok(guard) => {
                    drop(guard);
                    break;
                }
                Err(error) => assert_eq!(error.code, ErrorCode::ControlAlreadyRunning),
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    while clients.join_next().await.is_some() {}
}

#[tokio::test]
async fn total_frame_deadline_ends_a_trickling_connection() {
    let temp = Temp::new();
    let backend = BackendProbe::new(&temp.0);
    let interaction = async {
        ready(&temp.0).await;
        let paths = custody::preflight(&temp.0).unwrap();
        let mut stream = UnixStream::connect(paths.agent_sock).await.unwrap();
        stream.write_all(b"{").await.unwrap();
        for _ in 0..4 {
            tokio::time::sleep(Duration::from_millis(20)).await;
            stream.write_all(b" ").await.unwrap();
        }
        assert_eq!(
            timeout(Duration::from_millis(500), stream.read(&mut [0; 1]))
                .await
                .unwrap()
                .unwrap(),
            0
        );
        admin_request(&temp.0, json!({"op":"control.stop"}))
            .await
            .unwrap();
    };
    let (result, ()) = timeout(Duration::from_secs(10), async {
        tokio::join!(
            serve_with_deadlines(
                &temp.0,
                backend,
                std::future::pending(),
                Deadlines {
                    frame: Duration::from_millis(150),
                    response: Duration::from_secs(2),
                }
            ),
            interaction
        )
    })
    .await
    .unwrap();
    result.unwrap();
}

#[tokio::test]
async fn complete_success_error_and_outgoing_envelopes_have_size_limits() {
    let temp = Temp::new();
    let backend = BackendProbe::new(&temp.0);
    let interaction = async {
        ready(&temp.0).await;
        for op in ["large-error", "large-result"] {
            let error = admin_request(&temp.0, json!({"op":op})).await.unwrap_err();
            assert_eq!(error.code, ErrorCode::Internal);
            assert!(error.message.len() < 100);
        }
        let paths = custody::preflight(&temp.0).unwrap();
        assert_eq!(
            exchange(
                &paths.admin_sock,
                Channel::Admin,
                json!({"x":"\n".repeat(MAX_ADMIN_REQUEST_BYTES)})
            )
            .await
            .unwrap_err()
            .code,
            ErrorCode::Usage
        );
        admin_request(&temp.0, json!({"op":"control.stop"}))
            .await
            .unwrap();
    };
    let (result, ()) = timeout(Duration::from_secs(10), async {
        tokio::join!(serve(&temp.0, backend, std::future::pending()), interaction)
    })
    .await
    .unwrap();
    result.unwrap();
    let escaped = response(Err(ErrorBody::new(
        ErrorCode::Internal,
        "\n".repeat(MAX_RESPONSE_BYTES),
    )));
    assert!(escaped.len() <= MAX_RESPONSE_BYTES);
    assert_eq!(
        serde_json::from_slice::<Value>(&escaped).unwrap()["ok"],
        false
    );
}

#[tokio::test]
async fn incomplete_and_over_limit_frames_never_reach_backend() {
    for input in [b"{\"v\":1}".to_vec(), vec![b'x'; MAX_REQUEST_BYTES + 1]] {
        let mut reader = BufReader::new(input.as_slice());
        assert!(read_frame(&mut reader, MAX_REQUEST_BYTES).await.is_err());
    }
    let frame = b"{\"v\":1}\nnext\n";
    let mut reader = BufReader::new(frame.as_slice());
    assert_eq!(
        read_frame(&mut reader, 8).await.unwrap().unwrap(),
        b"{\"v\":1}\n"
    );
    assert_eq!(
        read_frame(&mut reader, 8).await.unwrap().unwrap(),
        b"next\n"
    );
    assert_eq!(read_frame(&mut reader, 8).await.unwrap(), None);
}

#[tokio::test]
async fn admin_accepts_private_artifacts_while_agent_requests_stay_small() {
    let temp = Temp::new();
    let backend = BackendProbe::new(&temp.0);
    let calls = Arc::clone(&backend.channels);
    let interaction = async {
        ready(&temp.0).await;
        let request = json!({"op":"echo", "artifact":"a".repeat(384 * 1024)});
        assert_eq!(
            agent_request(&temp.0, request.clone())
                .await
                .unwrap_err()
                .code,
            ErrorCode::Usage
        );
        assert_eq!(
            admin_request(&temp.0, request).await.unwrap()["channel"],
            "admin"
        );
        admin_request(&temp.0, json!({"op":"control.stop"}))
            .await
            .unwrap();
    };
    let (result, ()) = timeout(Duration::from_secs(10), async {
        tokio::join!(serve(&temp.0, backend, std::future::pending()), interaction)
    })
    .await
    .unwrap();
    result.unwrap();
    assert_eq!(*calls.lock().unwrap(), [Channel::Admin]);
}

#[tokio::test]
async fn idle_agent_connections_leave_room_for_administration() {
    let temp = Temp::new();
    let backend = BackendProbe::new(&temp.0);
    let interaction = async {
        ready(&temp.0).await;
        let paths = custody::preflight(&temp.0).unwrap();
        let mut idle = Vec::new();
        for _ in 0..MAX_CLIENTS {
            idle.push(UnixStream::connect(&paths.agent_sock).await.unwrap());
        }
        timeout(
            Duration::from_secs(1),
            admin_request(&temp.0, json!({"op":"control.hello"})),
        )
        .await
        .unwrap()
        .unwrap();
        admin_request(&temp.0, json!({"op":"control.stop"}))
            .await
            .unwrap();
        drop(idle);
    };
    let (result, ()) = timeout(Duration::from_secs(10), async {
        tokio::join!(serve(&temp.0, backend, std::future::pending()), interaction)
    })
    .await
    .unwrap();
    result.unwrap();
}

#[tokio::test]
async fn shutdown_refuses_queued_calls_without_dispatching_them() {
    let temp = Temp::new();
    let mut backend = BackendProbe::new(&temp.0);
    let (entered, entering) = oneshot::channel();
    let (release, releasing) = oneshot::channel();
    backend.entered = Some(entered);
    backend.release = Some(releasing);
    let calls = Arc::clone(&backend.channels);
    let interaction = async {
        ready(&temp.0).await;
        let first = admin_request(&temp.0, json!({"op":"wait"}));
        let others = async {
            entering.await.unwrap();
            // This request queues behind the held operation and times out. A
            // later stop must drain it without invoking its backend handler.
            assert_eq!(
                agent_request(&temp.0, json!({"op":"echo"}))
                    .await
                    .unwrap_err()
                    .code,
                ErrorCode::OwnerUnavailable
            );
            admin_request(&temp.0, json!({"op":"control.stop"}))
                .await
                .unwrap();
            release.send(()).unwrap();
        };
        let (_, ()) = tokio::join!(first, others);
    };
    let (result, ()) = timeout(Duration::from_secs(10), async {
        tokio::join!(
            serve_with_deadlines(
                &temp.0,
                backend,
                std::future::pending(),
                Deadlines {
                    frame: Duration::from_secs(2),
                    response: Duration::from_millis(80),
                }
            ),
            interaction
        )
    })
    .await
    .unwrap();
    result.unwrap();
    assert_eq!(*calls.lock().unwrap(), [Channel::Admin]);
}
