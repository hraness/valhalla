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
use vhalla_session::{ChatSession, Invitation, InvitationClaims, Pending};

// Invitations expire exclusively, while the existing pairing and route APIs
// use an inclusive last second. Keep that translation at this adapter boundary.
fn invitation_scope(claims: InvitationClaims) -> Result<PairingScope> {
    Ok(PairingScope {
        realm: claims.realm,
        room: claims.room,
        epoch: claims.epoch,
        expires_at: claims
            .expires_at
            .checked_sub(1)
            .ok_or(InvitationError::Malformed)?,
    })
}

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
        scope: PairingScope,
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
                    scope,
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
                let response = sign_chat(identity, &mut session, READY, scope.expires_at, now)?;
                let event = Event::Joined(session.outbound_context().session);
                Ok((Self::Chat(Box::new(session)), response, Some(event)))
            }
            Self::Chat(mut session) => {
                let verified = session.receive(raw, now)?;
                let response = sign_chat(
                    identity,
                    &mut session,
                    &ack_body(raw),
                    scope.expires_at,
                    now,
                )?;
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

/// The QUIC listen multiaddr for an IP literal: `/ip4/` or `/ip6/` on an
/// ephemeral UDP port. Names are not bind targets — a socket binds an
/// interface address — and this transport rejects `/dns4/` anyway, so a
/// non-IP input fails closed as an input error.
fn listen_multiaddr(host: &str) -> Result<Multiaddr> {
    let text = match host.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(_)) => format!("/ip4/{host}/udp/0/quic-v1"),
        Ok(std::net::IpAddr::V6(_)) => format!("/ip6/{host}/udp/0/quic-v1"),
        Err(_) => return Err(Error::Input("listen host must be an IP literal")),
    };
    text.parse()
        .map_err(|_| Error::Input("invalid listen host"))
}

/// A short-lived, bounded listener for one locally pinned application
/// peer — loopback unless an explicit `bind_on` host is given. Poll
/// `next` to drive it; at most four exact connection states exist.
/// Invalid input closes only its originating connection. Drop releases
/// sockets and the exclusive identity lock. No chat is persisted
/// automatically.
pub struct Listener {
    swarm: Swarm<Network>,
    identity: Identity,
    peer_app: [u8; 32],
    local_transport: [u8; 32],
    route: Route,
    scope: PairingScope,
    clock: Clock,
    connections: BTreeMap<ConnectionId, BoundConnection>,
    tick: tokio::time::Interval,
    closed: bool,
}
impl Listener {
    /// Bind an ephemeral loopback UDP port with a fresh OS-generated transport
    /// key. Both parties must independently pin each other's full app key.
    pub async fn bind(identity: Identity, peer_app: [u8; 32]) -> Result<Self> {
        Self::bind_on(identity, peer_app, "127.0.0.1").await
    }

    /// Same as [`bind`](Self::bind) but binds `listen` — an IPv4 or IPv6
    /// literal, never `host:port`. The advertised route carries that
    /// address, so the remote peer can dial it across machines when
    /// `listen` is a reachable interface such as a LAN or overlay address.
    /// An ephemeral port is still chosen; the pairing checks are unchanged.
    pub async fn bind_on(identity: Identity, peer_app: [u8; 32], listen: &str) -> Result<Self> {
        Self::bind_scoped(identity, peer_app, PairingScope::default(), None, listen).await
    }

    /// Bind using an owner-signed invitation. The local identity must be the
    /// invitation owner; the invited application key is pinned as the remote
    /// peer and the invitation's realm, room and epoch become the session
    /// pairing scope. Its exclusive expiry is converted to the pairing's
    /// inclusive last second. Verification occurs before any socket is bound.
    pub async fn bind_with_invitation(identity: Identity, invitation: Invitation) -> Result<Self> {
        Self::bind_with_invitation_on(identity, invitation, "127.0.0.1").await
    }

    /// Same as [`bind_with_invitation`](Self::bind_with_invitation) but binds
    /// `listen` like [`bind_on`](Self::bind_on).
    pub async fn bind_with_invitation_on(
        identity: Identity,
        invitation: Invitation,
        listen: &str,
    ) -> Result<Self> {
        let claims = invitation.verify_at(identity.public_key(), wall_time()?)?;
        let scope = invitation_scope(claims)?;
        Self::bind_scoped(
            identity,
            claims.invitee,
            scope,
            Some(scope.expires_at),
            listen,
        )
        .await
    }

    async fn bind_scoped(
        identity: Identity,
        peer_app: [u8; 32],
        mut scope: PairingScope,
        invited_expiry: Option<u64>,
        listen: &str,
    ) -> Result<Self> {
        validate_peer(identity.public_key(), peer_app)?;
        let clock = Clock::new()?;
        let expires_at =
            invited_expiry.unwrap_or(clock.last.checked_add(LIFETIME).ok_or(Error::Clock)?);
        if expires_at <= clock.last || expires_at.saturating_sub(clock.last) > LIFETIME {
            return Err(Error::Input(
                "invitation expiry must be within sixty seconds",
            ));
        }
        scope.expires_at = expires_at;
        let mut swarm = network::new(None)?;
        let local_transport = transport_key(*swarm.local_peer_id())?;
        swarm
            .listen_on(listen_multiaddr(listen)?)
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
            scope,
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
                            Some(bound) if bound.peer == peer => bound.state.receive(&self.identity, self.peer_app, self.local_transport, self.scope, &request, now),
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
    send_message_scoped(identity, peer_app, route, body, PairingScope::default()).await
}

/// Join a fresh connection using an invitation from an independently pinned
/// owner. `expected_owner` must come from local policy or a trusted handoff,
/// never from the invitation or route being checked. The local identity must
/// be the invitation's invitee. Verification precedes dialing; the invitation
/// scope is included in the authenticated session transcript, with its exclusive
/// expiry converted to the session's inclusive last second.
pub async fn send_message_with_invitation(
    identity: Identity,
    expected_owner: [u8; 32],
    invitation: Invitation,
    route: Route,
    body: &[u8],
) -> Result<Delivery> {
    let claims = invitation.verify_at(expected_owner, wall_time()?)?;
    if claims.invitee != identity.public_key() {
        return Err(Error::Input("invitation invitee does not match identity"));
    }
    let scope = invitation_scope(claims)?;
    if route.expires_at > scope.expires_at {
        return Err(Error::Input("route exceeds invitation lifetime"));
    }
    send_message_scoped(identity, expected_owner, route, body, scope).await
}

async fn send_message_scoped(
    identity: Identity,
    peer_app: [u8; 32],
    route: Route,
    body: &[u8],
    mut scope: PairingScope,
) -> Result<Delivery> {
    validate_peer(identity.public_key(), peer_app)?;
    if body.len() > vhalla_crypto::MAX_SIGNED_BODY_BYTES {
        return Err(Error::Input("chat exceeds signed body limit"));
    }
    let clock = Clock::new()?;
    if route.expires_at <= clock.last || route.expires_at.saturating_sub(clock.last) > LIFETIME {
        return Err(Error::Input("route must expire within sixty seconds"));
    }
    scope.expires_at = route.expires_at;
    tokio::time::timeout(
        REQUEST_DEADLINE,
        send_inner(identity, peer_app, route, body, scope, clock),
    )
    .await
    .map_err(|_| Error::Timeout)?
}

async fn send_inner(
    identity: Identity,
    peer_app: [u8; 32],
    route: Route,
    body: &[u8],
    scope: PairingScope,
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
                    scope,
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
    use vhalla_core::{Epoch, RealmId, RoomId};
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
                PairingScope {
                    expires_at: route.expires_at,
                    ..PairingScope::default()
                },
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
    async fn invitation_scope_authenticates_native_pairing_boundary() {
        let tmp = Temp::new();
        let owner = tmp.identity("owner");
        let invitee = tmp.identity("invitee");
        let wrong = tmp.identity("wrong");
        let late_invitee = tmp.identity("late-invitee");
        let owner_key = owner.public_key();
        let now = wall_time().unwrap();
        let invitation = owner
            .issue_invitation(
                invitee.public_key(),
                RealmId(9),
                RoomId(11),
                Epoch(13),
                now + 30,
                [7; 32],
            )
            .unwrap();
        let late_invitation = owner
            .issue_invitation(
                late_invitee.public_key(),
                RealmId(9),
                RoomId(11),
                Epoch(13),
                now + 30,
                [6; 32],
            )
            .unwrap();
        let mut listener = Listener::bind_with_invitation(owner, invitation)
            .await
            .unwrap();
        let route = listener.route().clone();
        assert_eq!(route.expires_at(), invitation.claims().expires_at - 1);
        let mut late_route = route.clone();
        late_route.expires_at = late_route.expires_at.saturating_add(1);
        assert!(matches!(
            send_message_with_invitation(wrong, owner_key, invitation, route.clone(), b"blocked")
                .await,
            Err(Error::Input("invitation invitee does not match identity"))
        ));
        assert!(matches!(
            send_message_with_invitation(
                late_invitee,
                owner_key,
                late_invitation,
                late_route,
                b"blocked"
            )
            .await,
            Err(Error::Input("route exceeds invitation lifetime"))
        ));
        let server = async {
            let mut joined = false;
            let mut received = false;
            let mut disconnected = false;
            while !disconnected {
                match listener.next().await.unwrap() {
                    Event::Joined(_) => joined = true,
                    Event::Message(message) => {
                        assert_eq!(message.envelope().body(), b"invited");
                        assert_eq!(message.envelope().realm(), RealmId(9));
                        assert_eq!(message.envelope().room(), RoomId(11));
                        assert_eq!(message.context().epoch, Epoch(13));
                        received = true;
                    }
                    Event::Rejected(error) => panic!("unexpected invitation rejection: {error:?}"),
                    Event::Disconnected => disconnected = true,
                }
            }
            assert!(joined && received);
        };
        let client =
            send_message_with_invitation(invitee, owner_key, invitation, route, b"invited");
        tokio::time::timeout(Duration::from_secs(12), async {
            let (result, ()) = tokio::join!(client, server);
            result.unwrap();
        })
        .await
        .unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn invitation_sender_rejects_owner_substitution_before_dialing() {
        let tmp = Temp::new();
        let expected = tmp.identity("expected-owner");
        let attacker = tmp.identity("attacker-owner");
        let invitee = tmp.identity("invitee");
        let now = wall_time().unwrap();
        let substituted = attacker
            .issue_invitation(
                invitee.public_key(),
                RealmId(9),
                RoomId(11),
                Epoch(13),
                now + 30,
                [7; 32],
            )
            .unwrap();
        // No server exists. Issuer rejection must precede all transport setup,
        // rather than failing later with a dial timeout or receipt mismatch.
        let peer = libp2p::identity::Keypair::ed25519_from_bytes([17; 32])
            .unwrap()
            .public()
            .to_peer_id();
        let route = Route::parse(
            &format!("/ip4/127.0.0.1/udp/9/quic-v1/p2p/{peer}"),
            now + 29,
        )
        .unwrap();
        assert!(matches!(
            send_message_with_invitation(
                invitee,
                expected.public_key(),
                substituted,
                route,
                b"must not be disclosed",
            )
            .await,
            Err(Error::Invitation(InvitationError::Issuer))
        ));
    }

    #[test]
    fn invitation_exclusive_expiry_bounds_earlier_handshakes_and_messages() {
        let tmp = Temp::new();
        let owner = tmp.identity("owner");
        let invitee = tmp.identity("invitee");
        let invitation = owner
            .issue_invitation(
                invitee.public_key(),
                RealmId(9),
                RoomId(11),
                Epoch(13),
                100,
                [7; 32],
            )
            .unwrap();
        let claims = invitation.verify_at(owner.public_key(), 98).unwrap();
        let scope = invitation_scope(claims).unwrap();
        assert_eq!(scope.expires_at, 99);
        let mut invalid = claims;
        invalid.expires_at = 0;
        assert!(matches!(
            invitation_scope(invalid),
            Err(Error::Invitation(InvitationError::Malformed))
        ));
        let transport = |seed| {
            transport_key(
                libp2p::identity::Keypair::ed25519_from_bytes([seed; 32])
                    .unwrap()
                    .public()
                    .to_peer_id(),
            )
            .unwrap()
        };
        let initiator_transport = transport(17);
        let responder_transport = transport(18);
        let pair = pairing(
            invitee.public_key(),
            owner.public_key(),
            initiator_transport,
            responder_transport,
            scope,
        );
        for finish_at in [99, 100] {
            let (pending, hello) = invitee
                .initiate_session(pair, initiator_transport, responder_transport, 98, 103)
                .unwrap();
            let inbound = Inbound::Hello {
                transport: initiator_transport,
                deadline: Instant::now() + HANDSHAKE_DEADLINE,
            };
            let (inbound, response, event) = inbound
                .receive(
                    &owner,
                    invitee.public_key(),
                    responder_transport,
                    scope,
                    &hello,
                    98,
                )
                .unwrap();
            assert!(event.is_none());
            let (mut sender, confirmation) =
                invitee.confirm_session(pending, &response, 98).unwrap();
            let result = inbound.receive(
                &owner,
                invitee.public_key(),
                responder_transport,
                scope,
                &confirmation,
                finish_at,
            );
            if finish_at == 100 {
                assert!(matches!(result, Err(Error::Session(Reject::Expired))));
                continue;
            }
            let (inbound, ready, event) = result.unwrap();
            assert!(matches!(event, Some(Event::Joined(_))));
            assert_eq!(sender.receive(&ready, 99).unwrap().envelope().body(), READY);
            let message = sign_chat(
                &invitee,
                &mut sender,
                b"last valid second",
                scope.expires_at,
                99,
            )
            .unwrap();
            let (inbound, acknowledgment, event) = inbound
                .receive(
                    &owner,
                    invitee.public_key(),
                    responder_transport,
                    scope,
                    &message,
                    99,
                )
                .unwrap();
            assert!(matches!(event, Some(Event::Message(_))));
            assert_eq!(
                sender
                    .receive(&acknowledgment, 99)
                    .unwrap()
                    .envelope()
                    .body(),
                ack_body(&message)
            );
            // Prepared before expiry, but delivered at the exclusive boundary.
            let delayed =
                sign_chat(&invitee, &mut sender, b"too late", scope.expires_at, 99).unwrap();
            assert!(matches!(
                inbound.receive(
                    &owner,
                    invitee.public_key(),
                    responder_transport,
                    scope,
                    &delayed,
                    100
                ),
                Err(Error::Session(Reject::Expired))
            ));
            assert!(matches!(
                sign_chat(
                    &invitee,
                    &mut sender,
                    b"also too late",
                    scope.expires_at,
                    100
                ),
                Err(Error::Session(Reject::Expired))
            ));
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn invitation_rejection_happens_before_socket_bind() {
        let tmp = Temp::new();
        let owner = tmp.identity("owner");
        let invitee = tmp.identity("invitee");
        let invitation = owner
            .issue_invitation(
                invitee.public_key(),
                RealmId(9),
                RoomId(11),
                Epoch(13),
                wall_time().unwrap().saturating_sub(1),
                [8; 32],
            )
            .unwrap();
        // Expired claims cannot reach the bind or transport layers.
        assert!(matches!(
            Listener::bind_with_invitation(owner, invitation).await,
            Err(Error::Invitation(vhalla_session::InvitationError::Expired))
        ));
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
            expired.receive(
                &b,
                a.public_key(),
                [2; 32],
                PairingScope {
                    expires_at: 100,
                    ..PairingScope::default()
                },
                &[],
                1,
            ),
            Err(Error::Timeout)
        ));
        let mut listener = Listener::bind(b, a.public_key()).await.unwrap();
        listener.clock.last = u64::MAX;
        assert!(matches!(listener.next().await, Err(Error::Clock)));
        listener.clock.last = wall_time().unwrap();
        assert!(matches!(listener.next().await, Err(Error::Closed)));
    }

    /// `bind_on` binds the named host and the advertised route carries it,
    /// so a remote peer can dial what it is given. A malformed host fails
    /// closed as an input error instead of reaching the socket layer.
    #[tokio::test(flavor = "current_thread")]
    async fn bind_on_binds_the_named_host_and_rejects_bad_hosts() {
        let tmp = Temp::new();
        let a = tmp.identity("a");
        let b = tmp.identity("b");
        let listener = Listener::bind_on(b, a.public_key(), "::1").await.unwrap();
        assert!(
            listener.route().address().contains("::1"),
            "route must advertise the bound host: {}",
            listener.route().address()
        );

        let bad = tmp.identity("bad");
        assert!(matches!(
            Listener::bind_on(bad, a.public_key(), "not a host!!").await,
            Err(Error::Input(_))
        ));
    }
}
