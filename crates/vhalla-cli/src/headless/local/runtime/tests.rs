use super::super::tests::{ready, Temp};
use super::super::{serve_factory, Launch};
use super::*;
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Mutex,
};

struct Probe {
    home: std::path::PathBuf,
    dropped_under_lock: Arc<AtomicBool>,
    invalidated: Arc<AtomicBool>,
    calls: Arc<AtomicUsize>,
    tick: Option<(oneshot::Sender<()>, oneshot::Receiver<()>)>,
    peer: Option<(oneshot::Sender<()>, oneshot::Receiver<()>)>,
    finished: Arc<AtomicBool>,
}
impl Probe {
    fn new(home: &Path) -> Self {
        Self {
            home: home.into(),
            dropped_under_lock: Arc::default(),
            invalidated: Arc::default(),
            calls: Arc::default(),
            tick: None,
            peer: None,
            finished: Arc::default(),
        }
    }
}
impl Drop for Probe {
    fn drop(&mut self) {
        self.dropped_under_lock.store(
            matches!(Guard::acquire(&self.home), Err(error) if error.code == ErrorCode::ControlAlreadyRunning),
            Ordering::SeqCst,
        );
    }
}
impl Backend for Probe {
    async fn dispatch(&mut self, _: Channel, request: Value) -> Result<Reply, ErrorBody> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(Reply::unrestricted(request))
    }
    fn invalidate(&mut self) {
        self.invalidated.store(true, Ordering::SeqCst);
    }
    async fn tick(&mut self) -> Result<(), ErrorBody> {
        if let Some((entered, release)) = self.tick.take() {
            let _ = entered.send(());
            let _ = release.await;
            self.finished.store(true, Ordering::SeqCst);
        }
        Ok(())
    }
    async fn peer(
        &mut self,
        authenticated_peer: [u8; 32],
        request: peer::Request,
    ) -> Result<peer::Reply, peer::PeerError> {
        assert_ne!(authenticated_peer, [0; 32]);
        assert!(matches!(request, peer::Request::Genesis { .. }));
        self.calls.fetch_add(1, Ordering::SeqCst);
        if let Some((entered, release)) = self.peer.take() {
            let _ = entered.send(());
            let _ = release.await;
            self.finished.store(true, Ordering::SeqCst);
        }
        Ok(peer::Reply::Genesis(vector("genesis_signed")))
    }
}

#[tokio::test]
async fn factory_opens_only_under_custody_and_publishes_endpoints_after_success() {
    let temp = Temp::new();
    let generation = Arc::new(Mutex::new(None));
    let (entered, entering) = oneshot::channel();
    let (release, releasing) = oneshot::channel();
    let factory_home = &temp.0;
    let factory_generation = &generation;
    let service = serve_factory(
        &temp.0,
        |value| async move {
            assert!(
                matches!(Guard::acquire(factory_home), Err(e) if e.code == ErrorCode::ControlAlreadyRunning)
            );
            *factory_generation.lock().unwrap() = Some(value);
            entered.send(()).unwrap();
            releasing.await.unwrap();
            Ok(Launch {
                backend: Probe::new(factory_home),
                endpoint: None,
            })
        },
        std::future::pending(),
    );
    let client = async {
        entering.await.unwrap();
        let paths = custody::preflight(&temp.0).unwrap();
        assert!(!paths.admin_sock.exists());
        assert!(!paths.agent_sock.exists());
        release.send(()).unwrap();
        ready(&temp.0).await;
        let hello = admin_request(&temp.0, json!({"op":"control.hello"}))
            .await
            .unwrap();
        assert_eq!(
            hello["generation"],
            generation.lock().unwrap().unwrap().to_string()
        );
        admin_request(&temp.0, json!({"op":"control.stop"}))
            .await
            .unwrap();
    };
    let (result, ()) = timeout(Duration::from_secs(5), async {
        tokio::join!(service, client)
    })
    .await
    .unwrap();
    result.unwrap();
    drop(Guard::acquire(&temp.0).unwrap());

    let held = Guard::acquire(&temp.0).unwrap();
    let called = AtomicBool::new(false);
    assert_eq!(
        serve_factory(
            &temp.0,
            |_| async {
                called.store(true, Ordering::SeqCst);
                Ok(Launch {
                    backend: Probe::new(&temp.0),
                    endpoint: None,
                })
            },
            std::future::pending()
        )
        .await
        .unwrap_err()
        .code,
        ErrorCode::ControlAlreadyRunning
    );
    assert!(!called.load(Ordering::SeqCst));
    drop(held);
}

#[tokio::test]
async fn failed_factory_preserves_state_and_releases_custody_without_sockets() {
    let temp = Temp::new();
    assert!(serve_factory(
        &temp.0,
        |_| async { Err::<Launch<Probe>, _>(unavailable()) },
        std::future::pending()
    )
    .await
    .is_err());
    let paths = custody::preflight(&temp.0).unwrap();
    assert!(!paths.admin_sock.exists());
    assert!(!paths.agent_sock.exists());
    assert!(paths.lock.exists());
    drop(Guard::acquire(&temp.0).unwrap());
}

#[tokio::test]
async fn stop_during_maintenance_joins_accepted_work_and_refuses_queued_calls() {
    let temp = Temp::new();
    let (entered, entering) = oneshot::channel();
    let (release, releasing) = oneshot::channel();
    let mut backend = Probe::new(&temp.0);
    backend.tick = Some((entered, releasing));
    let finished = Arc::clone(&backend.finished);
    let calls = Arc::clone(&backend.calls);
    let invalidated = Arc::clone(&backend.invalidated);
    let dropped = Arc::clone(&backend.dropped_under_lock);
    let service = serve_factory(
        &temp.0,
        |_| async {
            Ok(Launch {
                backend,
                endpoint: None,
            })
        },
        std::future::pending(),
    );
    let client = async {
        ready(&temp.0).await;
        entering.await.unwrap();
        let queued = admin_request(&temp.0, json!({"op":"echo"}));
        let stop = async {
            tokio::task::yield_now().await;
            admin_request(&temp.0, json!({"op":"control.stop"}))
                .await
                .unwrap();
            assert!(!finished.load(Ordering::SeqCst));
            assert!(
                matches!(Guard::acquire(&temp.0), Err(e) if e.code == ErrorCode::ControlAlreadyRunning)
            );
            release.send(()).unwrap();
        };
        let (answer, ()) = tokio::join!(queued, stop);
        assert!(answer.is_err());
    };
    let (result, ()) = timeout(Duration::from_secs(5), async {
        tokio::join!(service, client)
    })
    .await
    .unwrap();
    result.unwrap();
    assert!(finished.load(Ordering::SeqCst));
    assert!(invalidated.load(Ordering::SeqCst));
    assert!(dropped.load(Ordering::SeqCst));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

fn vector(name: &str) -> Vec<u8> {
    include_str!("../../../../../../vectors/direct-room-v1.txt")
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{name}=")))
        .unwrap()
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}
async fn endpoint() -> iroh::Endpoint {
    peer::endpoint_builder()
        .clear_ip_transports()
        .bind_addr("127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap())
        .unwrap()
        .bind()
        .await
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_peer_queue_keeps_admin_stop_responsive_and_drains_before_unlock() {
    let temp = Temp::new();
    let server = endpoint().await;
    let address = server.addr();
    let client = endpoint().await;
    let pin = vhalla_direct_room::RoomId::from_bytes(vector("genesis_id").try_into().unwrap());
    let (entered, entering) = oneshot::channel();
    let (release, releasing) = oneshot::channel();
    let mut backend = Probe::new(&temp.0);
    backend.peer = Some((entered, releasing));
    let finished = Arc::clone(&backend.finished);
    let dropped = Arc::clone(&backend.dropped_under_lock);
    let service = serve_factory(
        &temp.0,
        |_| async {
            Ok(Launch {
                backend,
                endpoint: Some(server),
            })
        },
        std::future::pending(),
    );
    let remote = async {
        ready(&temp.0).await;
        let connection = peer::Client::default();
        let call = connection.call(&client, address, peer::Request::Genesis { room: pin });
        let stop = async {
            entering.await.unwrap();
            // Native work accepted from a peer is awaited exactly like local
            // work, but stop needs neither queue nor the output write gate.
            admin_request(&temp.0, json!({"op":"control.stop"}))
                .await
                .unwrap();
            assert!(!finished.load(Ordering::SeqCst));
            assert!(
                matches!(Guard::acquire(&temp.0), Err(e) if e.code == ErrorCode::ControlAlreadyRunning)
            );
            release.send(()).unwrap();
        };
        let (answer, ()) = tokio::join!(call, stop);
        assert!(answer.is_err());
    };
    let (result, ()) = timeout(Duration::from_secs(10), async {
        tokio::join!(service, remote)
    })
    .await
    .unwrap();
    result.unwrap();
    assert!(finished.load(Ordering::SeqCst));
    assert!(dropped.load(Ordering::SeqCst));
    drop(Guard::acquire(&temp.0).unwrap());
    client.close().await;
}
