//! One durable-work owner, separate local/peer admission, and joined shutdown.

use super::super::{catalog::Hash, peer};
use super::*;
use tokio::{
    task::JoinHandle,
    time::{interval, MissedTickBehavior},
};

const MAX_PEER_QUEUED: usize = 16;
const MAINTENANCE_INTERVAL: Duration = Duration::from_millis(250);

/// Constructed only inside acquired service custody. An endpoint may have an
/// outbound clone in the backend; the server owns the other clone until drain.
pub(in crate::headless) struct Launch<B> {
    pub(in crate::headless) backend: B,
    pub(in crate::headless) endpoint: Option<iroh::Endpoint>,
}

struct PeerCall {
    authenticated_peer: [u8; 32],
    request: peer::Request,
    reply: oneshot::Sender<Result<peer::Reply, peer::PeerError>>,
}

#[derive(Clone)]
struct PeerQueue {
    queue: mpsc::Sender<PeerCall>,
    guard: Arc<Guard>,
    stop: watch::Sender<bool>,
}
impl peer::Handler for PeerQueue {
    async fn handle(
        &self,
        authenticated_peer: [u8; 32],
        request: peer::Request,
    ) -> Result<peer::Reply, peer::PeerError> {
        if *self.stop.borrow() || self.guard.check().is_err() {
            return Err(peer::PeerError::Unavailable);
        }
        let (reply, answer) = oneshot::channel();
        self.queue
            .try_send(PeerCall {
                authenticated_peer,
                request,
                reply,
            })
            .map_err(|_| peer::PeerError::Capacity)?;
        let result = answer.await.map_err(|_| peer::PeerError::Unavailable)?;
        if *self.stop.borrow() || self.guard.check().is_err() {
            return Err(peer::PeerError::Unavailable);
        }
        result
    }
}

struct Transport {
    listeners: JoinSet<()>,
    requests: mpsc::Receiver<Call>,
    peers: mpsc::Receiver<PeerCall>,
    network: Option<JoinHandle<Result<(), peer::PeerError>>>,
    frontend: Arc<Frontend>,
}
impl Drop for Transport {
    fn drop(&mut self) {
        self.frontend.stop.send_replace(true);
        // Local I/O owns no durable work and keeps its guard through actual
        // task drop. The network owner is NOT aborted: it observes this stop,
        // drains read workers, closes Iroh and retains the guard throughout.
        self.listeners.abort_all();
    }
}
struct Runtime<B> {
    // Rust drops fields in order, including during cancellation/unwinding.
    backend: B,
    transport: Transport,
}
struct Starting<B> {
    backend: B,
    endpoint: Option<iroh::Endpoint>,
    guard: Guard,
}

/// Acquire the supervisor lock before opening any backend handles. No local
/// endpoint is advertised until factory initialization and its checks finish.
pub(in crate::headless) async fn serve_factory<
    B: Backend,
    F: Future<Output = Result<Launch<B>, ErrorBody>>,
>(
    home: &Path,
    factory: impl FnOnce(Hash) -> F,
    shutdown: impl Future<Output = ()>,
) -> Result<(), ErrorBody> {
    let guard = Guard::acquire(home)?;
    let generation = Hash::parse(&guard.info().generation).map_err(|_| unavailable())?;
    let launch = factory(generation).await?;
    serve_owned(guard, launch, shutdown, Deadlines::default()).await
}

#[cfg(test)]
pub(super) async fn serve_with_deadlines(
    home: &Path,
    backend: impl Backend,
    shutdown: impl Future<Output = ()>,
    deadlines: Deadlines,
) -> Result<(), ErrorBody> {
    let guard = Guard::acquire(home)?;
    serve_owned(
        guard,
        Launch {
            backend,
            endpoint: None,
        },
        shutdown,
        deadlines,
    )
    .await
}

enum Work {
    Local(Call),
    Peer(PeerCall),
    Tick,
}
impl Work {
    fn abandoned(&self) -> bool {
        matches!(self, Self::Peer(call) if call.reply.is_closed())
    }
    fn refuse(self, error: ErrorBody) {
        match self {
            Self::Local(call) => {
                let _ = call.reply.send(Err(error));
            }
            Self::Peer(call) => {
                let _ = call.reply.send(Err(peer::PeerError::Unavailable));
            }
            Self::Tick => {}
        }
    }
}
enum Completion {
    Local(
        oneshot::Sender<Result<Reply, ErrorBody>>,
        Result<Reply, ErrorBody>,
    ),
    Peer(
        oneshot::Sender<Result<peer::Reply, peer::PeerError>>,
        Result<peer::Reply, peer::PeerError>,
    ),
    Tick(Result<(), ErrorBody>),
}
impl Completion {
    fn finish(self, failure: Option<ErrorBody>) -> Option<ErrorBody> {
        match self {
            Self::Local(reply, result) => {
                let _ = reply.send(failure.map_or(result, Err));
                None
            }
            Self::Peer(reply, result) => {
                let _ = reply.send(if failure.is_some() {
                    Err(peer::PeerError::Unavailable)
                } else {
                    result
                });
                None
            }
            // A successful accepted tick may finish during orderly shutdown.
            // There is no client reply to refuse; only an actual backend error
            // fails the service. Transport failure is retained by the caller.
            Self::Tick(result) => result.err(),
        }
    }
}

async fn serve_owned(
    guard: Guard,
    launch: Launch<impl Backend>,
    shutdown: impl Future<Output = ()>,
    deadlines: Deadlines,
) -> Result<(), ErrorBody> {
    let mut starting = Starting {
        backend: launch.backend,
        endpoint: launch.endpoint,
        guard,
    };
    starting.guard.check()?;
    let admin = starting.guard.bind(Channel::Admin)?;
    let agent = starting.guard.bind(Channel::Agent)?;
    let (queue, requests) = mpsc::channel(MAX_QUEUED);
    let (peer_queue, peers) = mpsc::channel(MAX_PEER_QUEUED);
    let (stop, mut stopping) = watch::channel(false);
    let frontend = Arc::new(Frontend {
        queue,
        stop,
        admin_clients: Arc::new(Semaphore::new(RESERVED_ADMIN_CLIENTS)),
        agent_clients: Arc::new(Semaphore::new(MAX_CLIENTS - RESERVED_ADMIN_CLIENTS)),
        guard: Arc::new(starting.guard),
        deadlines,
        output: Arc::new(RwLock::new(())),
    });
    let mut listeners = JoinSet::new();
    listeners.spawn(listener(admin, Channel::Admin, Arc::clone(&frontend)));
    listeners.spawn(listener(agent, Channel::Agent, Arc::clone(&frontend)));
    let network = starting.endpoint.map(|endpoint| {
        let handler = PeerQueue {
            queue: peer_queue,
            guard: Arc::clone(&frontend.guard),
            stop: frontend.stop.clone(),
        };
        let stop = frontend.stop.clone();
        let guard = Arc::clone(&frontend.guard);
        tokio::spawn(async move {
            let result = peer::serve(endpoint, handler, stop.subscribe()).await;
            let unexpected = !*stop.borrow();
            stop.send_replace(true);
            drop(guard);
            if unexpected {
                Err(peer::PeerError::Unavailable)
            } else {
                result
            }
        })
    });
    let mut runtime = Runtime {
        backend: starting.backend,
        transport: Transport {
            listeners,
            requests,
            peers,
            network,
            frontend,
        },
    };
    let mut maintenance = interval(MAINTENANCE_INTERVAL);
    maintenance.set_missed_tick_behavior(MissedTickBehavior::Skip);
    tokio::pin!(shutdown);
    let mut closing = false;
    let mut failure = None;
    while !closing {
        let work = tokio::select! {
            biased;
            () = &mut shutdown => break,
            () = stopped(&mut stopping) => break,
            work = async {
                // Fair selection below the urgent stop paths keeps a busy
                // peer or local client from starving maintenance/administration.
                tokio::select! {
                    call = runtime.transport.requests.recv() => call.map(Work::Local),
                    call = runtime.transport.peers.recv(), if runtime.transport.network.is_some() => call.map(Work::Peer),
                    _ = maintenance.tick() => Some(Work::Tick),
                }
            } => { let Some(work) = work else { break }; work }
        };
        if work.abandoned() {
            continue;
        }
        let output = Arc::clone(&runtime.transport.frontend.output);
        let _mutation = tokio::select! {
            biased;
            () = &mut shutdown => { work.refuse(unavailable()); break; }
            () = stopped(&mut stopping) => { work.refuse(unavailable()); break; }
            mutation = output.write() => mutation,
        };
        if work.abandoned() {
            continue;
        }
        if let Err(error) = runtime.transport.frontend.guard.check() {
            runtime.backend.invalidate();
            work.refuse(error.clone());
            failure = Some(error);
            break;
        }
        let completed = {
            // Native operations can have large async state. Keep one owned
            // allocation here instead of copying that state into every nested
            // service/CLI future. The drain loop still awaits accepted work.
            let mut operation = Box::pin(async {
                match work {
                    Work::Local(call) => Completion::Local(
                        call.reply,
                        runtime.backend.dispatch(call.channel, call.request).await,
                    ),
                    Work::Peer(call) => Completion::Peer(
                        call.reply,
                        runtime
                            .backend
                            .peer(call.authenticated_peer, call.request)
                            .await,
                    ),
                    Work::Tick => Completion::Tick(runtime.backend.tick().await),
                }
            });
            loop {
                tokio::select! {
                    biased;
                    () = &mut shutdown, if !closing => {
                        closing = true;
                        runtime.transport.frontend.stop.send_replace(true);
                    }
                    () = stopped(&mut stopping), if !closing => closing = true,
                    completed = &mut operation => break completed,
                }
            }
        };
        let release_error = match runtime.transport.frontend.guard.check() {
            Ok(()) if !closing => None,
            Ok(()) => Some(unavailable()),
            Err(error) => {
                failure = Some(error.clone());
                closing = true;
                Some(error)
            }
        };
        if release_error.is_some() {
            runtime.backend.invalidate();
        }
        if let Some(error) = completed.finish(release_error) {
            runtime.backend.invalidate();
            failure = Some(error);
            closing = true;
        }
    }
    runtime.transport.frontend.stop.send_replace(true);
    {
        let _mutation = runtime.transport.frontend.output.write().await;
        runtime.backend.invalidate();
    }
    runtime.transport.requests.close();
    runtime.transport.peers.close();
    while let Ok(call) = runtime.transport.requests.try_recv() {
        Work::Local(call).refuse(unavailable());
    }
    while let Ok(call) = runtime.transport.peers.try_recv() {
        Work::Peer(call).refuse(unavailable());
    }
    while runtime.transport.listeners.join_next().await.is_some() {}
    if let Some(network) = runtime.transport.network.take() {
        if !matches!(network.await, Ok(Ok(()))) && failure.is_none() {
            failure = Some(unavailable());
        }
    }
    failure.map_or(Ok(()), Err)
}

#[cfg(test)]
mod tests;
