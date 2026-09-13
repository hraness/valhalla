use super::*;
use futures::StreamExt;
use libp2p::{
    request_response::{self, Message},
    swarm::{ConnectionId, SwarmEvent},
    Swarm,
};
use network::{Network, NetworkEvent};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use vhalla_crypto::{SessionId, VerifiedEnvelope};
use vhalla_identity::Identity;
use vhalla_session::{ChatSession, Pending};

/// An admitted observation. Chat is untrusted data even after authentication.
pub enum Event {
    /// The pinned application peer completed a fresh handshake.
    Joined(SessionId),
    /// A new signed chat passed the current connection's replay/context checks.
    Message(Box<VerifiedEnvelope>),
    /// One connection was rejected; other connections can continue.
    Rejected(Error),
    /// An observed transport connection closed and its session was discarded.
    Disconnected,
}

/// A verified peer acknowledgment of one exact signed frame. This is a volatile
/// receipt, not proof of durable storage, human attention or agent execution.
pub struct Delivery {
    acknowledgment: VerifiedEnvelope,
    digest: [u8; 32],
}
impl Delivery {
    /// Receiver's signed acknowledgment; its signer and context remain inspectable.
    #[must_use]
    pub fn acknowledgment(&self) -> &VerifiedEnvelope {
        &self.acknowledgment
    }
    /// SHA-256 of the exact signed frame the peer acknowledged.
    #[must_use]
    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
}

enum Inbound {
    Hello {
        transport: [u8; 32],
        deadline: Instant,
    },
    Confirm {
        pending: Box<Pending>,
        deadline: Instant,
    },
    Chat(Box<ChatSession>),
}
impl Inbound {
    fn timed_out(&self) -> bool {
        match self {
            Self::Hello { deadline, .. } | Self::Confirm { deadline, .. } => {
                Instant::now() >= *deadline
            }
            Self::Chat(_) => false,
        }
    }
    fn receive(
        self,
        identity: &Identity,
        peer_app: [u8; 32],
        local_transport: [u8; 32],
        expires: u64,
        raw: &[u8],
        now: u64,
    ) -> Result<(Self, Vec<u8>, Option<Event>)> {
        if self.timed_out() {
            return Err(Error::Timeout);
        }
        match self {
            Self::Hello {
                transport,
                deadline,
            } => {
                let pair = pairing(
                    peer_app,
                    identity.public_key(),
                    transport,
                    local_transport,
                    expires,
                );
                let (pending, response) = identity.respond_session(
                    pair,
                    local_transport,
                    transport,
                    raw,
                    now,
                    now.saturating_add(5),
                )?;
                Ok((
                    Self::Confirm {
                        pending: Box::new(pending),
                        deadline,
                    },
                    response,
                    None,
                ))
            }
            Self::Confirm { pending, .. } => {
                let mut session = (*pending).finish(raw, now)?;
                let response = sign_chat(identity, &mut session, READY, expires, now)?;
                let event = Event::Joined(session.outbound_context().session);
                Ok((Self::Chat(Box::new(session)), response, Some(event)))
            }
            Self::Chat(mut session) => {
                let verified = session.receive(raw, now)?;
                let response = sign_chat(identity, &mut session, &ack_body(raw), expires, now)?;
                Ok((
                    Self::Chat(session),
                    response,
                    Some(Event::Message(Box::new(verified))),
                ))
            }
        }
    }
}

struct BoundConnection {
    peer: PeerId,
    state: Inbound,
}

/// A short-lived, bounded loopback listener for one locally pinned application
/// peer. Poll `next` to drive it; at most four exact connection states exist.
/// Invalid input closes only its originating connection. Drop releases sockets
/// and the exclusive identity lock. No chat is persisted automatically.
pub struct Listener {
    swarm: Swarm<Network>,
    identity: Identity,
    peer_app: [u8; 32],
    local_transport: [u8; 32],
    route: Route,
    clock: Clock,
    connections: BTreeMap<ConnectionId, BoundConnection>,
    tick: tokio::time::Interval,
    closed: bool,
}
impl Listener {
    /// Bind an ephemeral loopback UDP port with a fresh OS-generated transport
    /// key. Both parties must independently pin each other's full app key.
    pub async fn bind(identity: Identity, peer_app: [u8; 32]) -> Result<Self> {
        validate_peer(identity.public_key(), peer_app)?;
        let clock = Clock::new()?;
        let expires_at = clock.last.checked_add(LIFETIME).ok_or(Error::Clock)?;
        let mut swarm = network::new(None)?;
        let local_transport = transport_key(*swarm.local_peer_id())?;
        swarm
            .listen_on(
                "/ip4/127.0.0.1/udp/0/quic-v1"
                    .parse()
                    .expect("literal address"),
            )
            .map_err(transport)?;
        let address = tokio::time::timeout(REQUEST_DEADLINE, async {
            loop {
                match swarm.select_next_some().await {
                    SwarmEvent::NewListenAddr { address, .. } => return Ok(address),
                    SwarmEvent::ListenerError { error, .. } => return Err(transport(error)),
                    _ => {}
                }
            }
        })
        .await
        .map_err(|_| Error::Timeout)??;
        let route = Route::parse(
            &format!("{address}/p2p/{}", swarm.local_peer_id()),
            expires_at,
        )?;
        let mut tick = tokio::time::interval(Duration::from_millis(100));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        Ok(Self {
            swarm,
            identity,
            peer_app,
            local_transport,
            route,
            clock,
            connections: BTreeMap::new(),
            tick,
            closed: false,
        })
    }
    /// Untrusted address hint for the already pinned peer.
    #[must_use]
    pub fn route(&self) -> &Route {
        &self.route
    }

    fn check_clock(&mut self) -> Result<u64> {
        match self.clock.check_lifetime(self.route.expires_at) {
            Ok(now) => Ok(now),
            Err(error) => {
                self.closed = true;
                self.connections.clear();
                for peer in self.swarm.connected_peers().copied().collect::<Vec<_>>() {
                    let _ = self.swarm.disconnect_peer_id(peer);
                }
                Err(error)
            }
        }
    }

    /// Drive bounded network progress until an observation or lifetime failure.
    /// A fatal clock/lifetime error permanently closes this adapter instance.
    pub async fn next(&mut self) -> Result<Event> {
        if self.closed {
            return Err(Error::Closed);
        }
        loop {
            self.check_clock()?;
            tokio::select! {
                biased;
                _ = self.tick.tick() => {
                    let expired: Vec<_> = self.connections.iter().filter(|(_, c)| c.state.timed_out()).map(|(id, _)| *id).collect();
                    for id in expired { self.connections.remove(&id); self.swarm.close_connection(id); }
                }
                event = self.swarm.select_next_some() => match event {
                    SwarmEvent::ConnectionEstablished { peer_id, connection_id, .. } => {
                        if self.connections.len() >= MAX_CONNECTIONS as usize || self.connections.contains_key(&connection_id) {
                            self.swarm.close_connection(connection_id); continue;
                        }
                        match transport_key(peer_id) {
                            Ok(transport) => { self.connections.insert(connection_id, BoundConnection { peer: peer_id,
                                state: Inbound::Hello { transport, deadline: Instant::now() + HANDSHAKE_DEADLINE } }); }
                            Err(error) => { self.swarm.close_connection(connection_id); return Ok(Event::Rejected(error)); }
                        }
                    }
                    SwarmEvent::Behaviour(NetworkEvent::Chat(request_response::Event::Message { peer, connection_id,
                        message: Message::Request { request, channel, .. } })) => {
                        let now = self.check_clock()?;
                        let state = self.connections.remove(&connection_id);
                        let result = match state {
                            Some(bound) if bound.peer == peer => bound.state.receive(&self.identity, self.peer_app, self.local_transport, self.route.expires_at, &request, now),
                            _ => Err(Error::Input("request does not belong to an admitted connection")),
                        };
                        match result {
                            Ok((state, response, event)) => {
                                if self.swarm.behaviour_mut().chat.send_response(channel, response).is_err() {
                                    self.swarm.close_connection(connection_id); return Ok(Event::Rejected(Error::Closed));
                                }
                                self.connections.insert(connection_id, BoundConnection { peer, state });
                                if let Some(event) = event { return Ok(event); }
                            }
                            Err(error) => { self.swarm.close_connection(connection_id); return Ok(Event::Rejected(error)); }
                        }
                    }
                    SwarmEvent::Behaviour(NetworkEvent::Chat(request_response::Event::InboundFailure { connection_id, error, .. })) => {
                        // Closing a rejected connection can itself generate a
                        // late response failure. Its state is already consumed.
                        if self.connections.remove(&connection_id).is_some() {
                            self.swarm.close_connection(connection_id);
                            return Ok(Event::Rejected(transport(error)));
                        }
                    }
                    SwarmEvent::ConnectionClosed { connection_id, .. } => {
                        self.connections.remove(&connection_id); return Ok(Event::Disconnected);
                    }
                    SwarmEvent::ListenerError { error, .. } => { self.closed = true; return Err(transport(error)); }
                    _ => {}
                }
            }
        }
    }
}

fn sign_chat(
    identity: &Identity,
    session: &mut ChatSession,
    body: &[u8],
    expires: u64,
    now: u64,
) -> Result<Vec<u8>> {
    let envelope = session.prepare_chat(body, now)?;
    identity
        .sign_envelope(envelope, session.outbound_context(), expires)
        .map_err(|e| Error::Transport(format!("sign: {e:?}")))?
        .encode()
        .map_err(|e| Error::Transport(format!("encode: {e:?}")))
}
fn ack_body(raw: &[u8]) -> Vec<u8> {
    let mut body = b"vhalla/native/received/v1".to_vec();
    body.extend_from_slice(&Sha256::digest(raw));
    body
}

enum Outbound {
    Hello(Pending),
    Confirm(ChatSession),
    Chat(ChatSession, Vec<u8>, [u8; 32]),
}

/// Join a fresh connection, send one bounded chat, and verify the peer's signed
/// acknowledgment of that exact frame. The complete operation, including close,
/// has a ten-second monotonic deadline. Errors drop all session/transport state;
/// there is no automatic retry or claim of durable delivery.
pub async fn send_message(
    identity: Identity,
    peer_app: [u8; 32],
    route: Route,
    body: &[u8],
) -> Result<Delivery> {
    validate_peer(identity.public_key(), peer_app)?;
    if body.len() > vhalla_crypto::MAX_SIGNED_BODY_BYTES {
        return Err(Error::Input("chat exceeds signed body limit"));
    }
    let clock = Clock::new()?;
    if route.expires_at <= clock.last || route.expires_at.saturating_sub(clock.last) > LIFETIME {
        return Err(Error::Input("route must expire within sixty seconds"));
    }
    tokio::time::timeout(
        REQUEST_DEADLINE,
        send_inner(identity, peer_app, route, body, clock),
    )
    .await
    .map_err(|_| Error::Timeout)?
}

async fn send_inner(
    identity: Identity,
    peer_app: [u8; 32],
    route: Route,
    body: &[u8],
    mut clock: Clock,
) -> Result<Delivery> {
    let mut swarm = network::new(Some(route.peer))?;
    let local_transport = transport_key(*swarm.local_peer_id())?;
    swarm.dial(route.address.clone()).map_err(transport)?;
    let mut connection = None;
    let mut pending_request = None;
    let mut state = None;
    let mut delivery = None;
    loop {
        let event = swarm.select_next_some().await;
        let now = clock.check_lifetime(route.expires_at)?;
        match event {
            SwarmEvent::ConnectionEstablished {
                peer_id,
                connection_id,
                ..
            } => {
                if connection.is_some() || peer_id != route.peer {
                    return Err(Error::Input("unexpected transport connection"));
                }
                let remote_transport = transport_key(peer_id)?;
                let pair = pairing(
                    identity.public_key(),
                    peer_app,
                    local_transport,
                    remote_transport,
                    route.expires_at,
                );
                let (pending, hello) = identity.initiate_session(
                    pair,
                    local_transport,
                    remote_transport,
                    now,
                    now.saturating_add(5),
                )?;
                connection = Some(connection_id);
                pending_request = Some(swarm.behaviour_mut().chat.send_request(&peer_id, hello));
                state = Some(Outbound::Hello(pending));
            }
            SwarmEvent::Behaviour(NetworkEvent::Chat(request_response::Event::Message {
                peer,
                connection_id,
                message:
                    Message::Response {
                        request_id,
                        response,
                    },
            })) => {
                if peer != route.peer
                    || connection != Some(connection_id)
                    || pending_request != Some(request_id)
                {
                    return Err(Error::Input(
                        "response belongs to a different request or connection",
                    ));
                }
                let request = match state.take().ok_or(Error::Closed)? {
                    Outbound::Hello(pending) => {
                        let (session, confirmation) =
                            identity.confirm_session(pending, &response, now)?;
                        state = Some(Outbound::Confirm(session));
                        confirmation
                    }
                    Outbound::Confirm(mut session) => {
                        let verified = session.receive(&response, now)?;
                        if verified.envelope().body() != READY {
                            return Err(Error::Input("invalid signed readiness message"));
                        }
                        let message =
                            sign_chat(&identity, &mut session, body, route.expires_at, now)?;
                        let digest = Sha256::digest(&message).into();
                        state = Some(Outbound::Chat(session, ack_body(&message), digest));
                        message
                    }
                    Outbound::Chat(mut session, expected, digest) => {
                        let acknowledgment = session.receive(&response, now)?;
                        if acknowledgment.envelope().body() != expected {
                            return Err(Error::Input("acknowledgment does not match sent frame"));
                        }
                        delivery = Some(Delivery {
                            acknowledgment,
                            digest,
                        });
                        swarm.disconnect_peer_id(peer).map_err(|_| Error::Closed)?;
                        continue;
                    }
                };
                pending_request = Some(swarm.behaviour_mut().chat.send_request(&peer, request));
            }
            SwarmEvent::ConnectionClosed { connection_id, .. }
                if connection == Some(connection_id) =>
            {
                // Quinn flushes its close datagram asynchronously. Integration
                // tests also require receiver-side connection-close evidence.
                tokio::time::sleep(Duration::from_millis(50)).await;
                return delivery.ok_or(Error::Closed);
            }
            SwarmEvent::OutgoingConnectionError { error, .. } => return Err(transport(error)),
            SwarmEvent::Behaviour(NetworkEvent::Chat(
                request_response::Event::OutboundFailure { error, .. },
            )) => return Err(transport(error)),
            // A responder never initiates requests in this version.
            SwarmEvent::Behaviour(NetworkEvent::Chat(request_response::Event::Message {
                message: Message::Request { .. },
                ..
            })) => return Err(Error::Input("unexpected inbound request")),
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::DirBuilderExt, path::PathBuf};
    use vhalla_crypto::VerifyError;

    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            let mut random = [0; 16];
            getrandom::fill(&mut random).unwrap();
            let path = std::env::temp_dir().join(format!(
                "vhalla-native-test-{:032x}",
                u128::from_be_bytes(random)
            ));
            fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
            Self(path)
        }
        fn identity(&self, name: &str) -> Identity {
            Identity::create_new(self.0.join(name)).unwrap()
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    // Test-only raw peer: production exposes only bounded signed chat sending.
    struct RawPeer {
        swarm: Swarm<Network>,
        peer: PeerId,
        id: ConnectionId,
        session: ChatSession,
    }
    impl RawPeer {
        async fn connect(identity: &Identity, peer_app: [u8; 32], route: &Route) -> Self {
            let mut swarm = network::new(Some(route.peer)).unwrap();
            swarm.dial(route.address.clone()).unwrap();
            let id = loop {
                match swarm.select_next_some().await {
                    SwarmEvent::ConnectionEstablished {
                        peer_id,
                        connection_id,
                        ..
                    } => {
                        assert_eq!(peer_id, route.peer);
                        break connection_id;
                    }
                    SwarmEvent::OutgoingConnectionError { error, .. } => panic!("dial: {error}"),
                    _ => {}
                }
            };
            let local = transport_key(*swarm.local_peer_id()).unwrap();
            let remote = transport_key(route.peer).unwrap();
            let now = wall_time().unwrap();
            let pair = pairing(
                identity.public_key(),
                peer_app,
                local,
                remote,
                route.expires_at,
            );
            let (pending, hello) = identity
                .initiate_session(pair, local, remote, now, now + 5)
                .unwrap();
            let response = exchange(&mut swarm, route.peer, id, hello).await.unwrap();
            let (mut session, confirmation) = identity
                .confirm_session(pending, &response, wall_time().unwrap())
                .unwrap();
            let ready = exchange(&mut swarm, route.peer, id, confirmation)
                .await
                .unwrap();
            assert_eq!(
                session
                    .receive(&ready, wall_time().unwrap())
                    .unwrap()
                    .envelope()
                    .body(),
                READY
            );
            Self {
                swarm,
                peer: route.peer,
                id,
                session,
            }
        }
        async fn raw(&mut self, frame: Vec<u8>) -> Result<Vec<u8>> {
            exchange(&mut self.swarm, self.peer, self.id, frame).await
        }
        fn frame(&mut self, identity: &Identity, body: &[u8], expires: u64) -> Vec<u8> {
            sign_chat(
                identity,
                &mut self.session,
                body,
                expires,
                wall_time().unwrap(),
            )
            .unwrap()
        }
    }
    async fn exchange(
        swarm: &mut Swarm<Network>,
        peer: PeerId,
        id: ConnectionId,
        raw: Vec<u8>,
    ) -> Result<Vec<u8>> {
        let request = swarm.behaviour_mut().chat.send_request(&peer, raw);
        loop {
            match swarm.select_next_some().await {
                SwarmEvent::Behaviour(NetworkEvent::Chat(request_response::Event::Message {
                    peer: got,
                    connection_id,
                    message:
                        Message::Response {
                            request_id,
                            response,
                        },
                })) => {
                    assert_eq!((got, connection_id, request_id), (peer, id, request));
                    return Ok(response);
                }
                SwarmEvent::Behaviour(NetworkEvent::Chat(
                    request_response::Event::OutboundFailure { error, .. },
                )) => return Err(transport(error)),
                SwarmEvent::ConnectionClosed { connection_id, .. } if connection_id == id => {
                    return Err(Error::Closed)
                }
                _ => {}
            }
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn real_connections_reject_cross_session_replays_without_harming_live_peer() {
        let tmp = Temp::new();
        let a = tmp.identity("a");
        let b = tmp.identity("b");
        let b_key = b.public_key();
        let mut listener = Listener::bind(b, a.public_key()).await.unwrap();
        let route = listener.route().clone();
        let server = async {
            let (mut joins, mut messages, mut rejects, mut disconnected) = (0, 0, 0, 0);
            while disconnected < 1 || messages < 2 || rejects < 1 {
                match listener.next().await.unwrap() {
                    Event::Joined(_) => joins += 1,
                    Event::Message(message) => {
                        assert_eq!(message.signer_key(), &a.public_key());
                        assert_eq!(
                            message.envelope().body().len(),
                            vhalla_crypto::MAX_SIGNED_BODY_BYTES
                        );
                        messages += 1;
                    }
                    Event::Rejected(Error::Session(Reject::Verify(
                        VerifyError::SessionMismatch,
                    ))) => rejects += 1,
                    Event::Rejected(error) => panic!("unexpected rejection: {error:?}"),
                    Event::Disconnected => disconnected += 1,
                }
            }
            assert_eq!((joins, messages, rejects), (2, 2, 1));
            while listener.next().await.is_ok() {}
        };
        let client = async {
            let body = vec![0xa5; vhalla_crypto::MAX_SIGNED_BODY_BYTES];
            let mut first = RawPeer::connect(&a, b_key, &route).await;
            let original = first.frame(&a, &body, route.expires_at);
            let ack = first.raw(original.clone()).await.unwrap();
            assert_eq!(
                first
                    .session
                    .receive(&ack, wall_time().unwrap())
                    .unwrap()
                    .envelope()
                    .body(),
                ack_body(&original)
            );
            // Another transport connection authenticates the same app key but
            // gets independent nonces/state. Its replay must not close first.
            let mut second = RawPeer::connect(&a, b_key, &route).await;
            assert_ne!(
                first.session.outbound_context().session,
                second.session.outbound_context().session
            );
            assert!(second.raw(original).await.is_err());
            let fresh = first.frame(&a, &body, route.expires_at);
            let ack = first.raw(fresh.clone()).await.unwrap();
            assert_eq!(
                first
                    .session
                    .receive(&ack, wall_time().unwrap())
                    .unwrap()
                    .envelope()
                    .body(),
                ack_body(&fresh)
            );
        };
        // Both futures and all sockets are owned by this bounded test. The
        // listener keeps driving until the client verifies its final reply.
        tokio::time::timeout(Duration::from_secs(12), async {
            tokio::select! {
                _ = server => panic!("listener ended before client"),
                _ = client => {}
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn expired_handshake_state_and_clock_fail_closed() {
        let tmp = Temp::new();
        let a = tmp.identity("a");
        let b = tmp.identity("b");
        let expired = Inbound::Hello {
            transport: [1; 32],
            deadline: Instant::now(),
        };
        assert!(matches!(
            expired.receive(&b, a.public_key(), [2; 32], 100, &[], 1),
            Err(Error::Timeout)
        ));
        let mut listener = Listener::bind(b, a.public_key()).await.unwrap();
        listener.clock.last = u64::MAX;
        assert!(matches!(listener.next().await, Err(Error::Clock)));
        listener.clock.last = wall_time().unwrap();
        assert!(matches!(listener.next().await, Err(Error::Closed)));
    }
}
