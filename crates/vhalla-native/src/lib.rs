#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![cfg(unix)]

//! Experimental, loopback-only paired chat over real QUIC sockets.
//!
//! Full application keys are explicit local pins. Route advertisements are
//! untrusted hints, never membership grants. Fresh transport keys are generated
//! per process; authenticated QUIC identities bind the application handshake.
//! This adapter has no policy/host execution API and never evaluates chat text.
//! Public networking, discovery, browser interoperability and durable delivery
//! remain separate admission gates.

mod codec;
mod connection;
mod network;
mod spent;

pub use connection::{send_message, send_message_with_invitation, Delivery, Event, Listener};
pub use spent::{SpentError, SpentFile, SPENT_CAPACITY};
pub use vhalla_session::{Invitation, INVITATION_BYTES};

use libp2p::{identity::PublicKey, multiaddr::Protocol, Multiaddr, PeerId};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use vhalla_core::{Epoch, RealmId, RoomId};
use vhalla_crypto::VerifyingKey;
use vhalla_identity::IdentityError;
use vhalla_session::{InvitationError, Pairing, Reject};

const MAX_FRAME: usize = 64 * 1024;
const MAX_CONNECTIONS: u32 = 4;
const REQUEST_DEADLINE: Duration = Duration::from_secs(10);
const HANDSHAKE_DEADLINE: Duration = Duration::from_secs(5);
const LIFETIME: u64 = 60;
const READY: &[u8] = b"vhalla/native/ready/v1";

#[derive(Clone, Copy)]
struct PairingScope {
    realm: RealmId,
    room: RoomId,
    epoch: Epoch,
    expires_at: u64,
}
impl PairingScope {
    const fn default() -> Self {
        Self {
            realm: RealmId(1),
            room: RoomId(2),
            epoch: Epoch(1),
            expires_at: 0,
        }
    }
}

/// Native adapter failures. Errors never authorize retrying a consumed session.
#[derive(Debug)]
pub enum Error {
    /// Local input violated a bound, pin, or route restriction.
    Input(&'static str),
    /// Private identity operation failed.
    Identity(IdentityError),
    /// Authenticated protocol admission rejected a message.
    Session(Reject),
    /// Owner-signed pairing invitation failed verification or was expired.
    Invitation(InvitationError),
    /// Bounded transport operation failed.
    Transport(String),
    /// Operation's monotonic deadline elapsed.
    Timeout,
    /// Local wall clock is unavailable or moved backwards.
    Clock,
    /// Connection or listener lifetime ended.
    Closed,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Error {}
impl From<IdentityError> for Error {
    fn from(value: IdentityError) -> Self {
        Self::Identity(value)
    }
}
impl From<Reject> for Error {
    fn from(value: Reject) -> Self {
        Self::Session(value)
    }
}
impl From<InvitationError> for Error {
    fn from(value: InvitationError) -> Self {
        Self::Invitation(value)
    }
}
type Result<T> = std::result::Result<T, Error>;
fn transport(error: impl std::fmt::Display) -> Error {
    Error::Transport(error.to_string())
}

/// Bounded, untrusted loopback address and expiry. It does not identify an
/// application owner or grant permission to participate.
#[derive(Clone, Debug)]
pub struct Route {
    address: Multiaddr,
    peer: PeerId,
    expires_at: u64,
}
impl Route {
    /// Parse only a literal loopback IPv4 QUIC address with an Ed25519 PeerId.
    /// No DNS, relays, non-loopback targets, extra protocols or unbounded text.
    pub fn parse(address: &str, expires_at: u64) -> Result<Self> {
        if address.len() > 256 {
            return Err(Error::Input("route exceeds 256 bytes"));
        }
        if expires_at == 0 {
            return Err(Error::Input("route expiry is required"));
        }
        let address: Multiaddr = address.parse().map_err(transport)?;
        let parts: Vec<_> = address.iter().collect();
        let peer = match parts.as_slice() {
            [Protocol::Ip4(ip), Protocol::Udp(port), Protocol::QuicV1, Protocol::P2p(peer)]
                if ip.is_loopback() && *port != 0 =>
            {
                *peer
            }
            _ => {
                return Err(Error::Input(
                    "expected loopback IPv4 QUIC route with peer ID",
                ))
            }
        };
        transport_key(peer)?;
        Ok(Self {
            address,
            peer,
            expires_at,
        })
    }
    /// Address for explicit out-of-band handoff. Not a signed invitation.
    #[must_use]
    pub fn address(&self) -> String {
        self.address.to_string()
    }
    /// Inclusive Unix-second expiry of this short-lived connection offer.
    #[must_use]
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }
}

fn validate_peer(local: [u8; 32], remote: [u8; 32]) -> Result<()> {
    if local == remote {
        return Err(Error::Input("application peers must differ"));
    }
    let key =
        VerifyingKey::from_bytes(&remote).map_err(|_| Error::Input("invalid application key"))?;
    if key.is_weak() {
        return Err(Error::Input("weak application key"));
    }
    Ok(())
}

// Only an authenticated ConnectionEstablished PeerId may be used as observed
// transport evidence. Parsing a route alone supplies a dial pin, not evidence.
fn transport_key(peer: PeerId) -> Result<[u8; 32]> {
    let hash = peer.as_ref();
    if hash.code() != 0 {
        return Err(Error::Input("transport key must be inline Ed25519"));
    }
    let public = PublicKey::try_decode_protobuf(hash.digest()).map_err(transport)?;
    if public.to_peer_id() != peer {
        return Err(Error::Input("noncanonical transport identity"));
    }
    let bytes = public.try_into_ed25519().map_err(transport)?.to_bytes();
    let key =
        VerifyingKey::from_bytes(&bytes).map_err(|_| Error::Input("invalid transport key"))?;
    if key.is_weak() {
        return Err(Error::Input("weak transport key"));
    }
    Ok(bytes)
}

fn pairing(
    initiator: [u8; 32],
    responder: [u8; 32],
    initiator_transport: [u8; 32],
    responder_transport: [u8; 32],
    scope: PairingScope,
) -> Pairing {
    Pairing {
        initiator,
        responder,
        initiator_transport,
        responder_transport,
        realm: scope.realm,
        room: scope.room,
        epoch: scope.epoch,
        expires_at: scope.expires_at,
    }
}

struct Clock {
    last: u64,
    started: Instant,
}
impl Clock {
    fn new() -> Result<Self> {
        Ok(Self {
            last: wall_time()?,
            started: Instant::now(),
        })
    }
    fn now(&mut self) -> Result<u64> {
        let now = wall_time()?;
        if now < self.last {
            return Err(Error::Clock);
        }
        self.last = now;
        Ok(now)
    }
    fn check_lifetime(&mut self, expires: u64) -> Result<u64> {
        let now = self.now()?;
        if now > expires || self.started.elapsed() > Duration::from_secs(LIFETIME) {
            return Err(Error::Closed);
        }
        Ok(now)
    }
}
fn wall_time() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| Error::Clock)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    #[test]
    fn routes_reject_nonlocal_missing_or_extra_protocols() {
        let key = libp2p::identity::Keypair::ed25519_from_bytes([1; 32]).unwrap();
        let peer = key.public().to_peer_id();
        assert!(Route::parse(&format!("/ip4/127.0.0.1/udp/7/quic-v1/p2p/{peer}"), 1).is_ok());
        for raw in [
            format!("/ip4/8.8.8.8/udp/7/quic-v1/p2p/{peer}"),
            format!("/ip4/127.0.0.1/udp/0/quic-v1/p2p/{peer}"),
            "/ip4/127.0.0.1/udp/7/quic-v1".into(),
            format!("/dns4/localhost/udp/7/quic-v1/p2p/{peer}"),
            format!("/ip4/127.0.0.1/udp/7/quic-v1/p2p/{peer}/p2p-circuit"),
        ] {
            assert!(Route::parse(&raw, 1).is_err());
        }
    }
    proptest! {
        #[test]
        fn arbitrary_route_is_bounded(raw in ".{0,1024}") { let _ = Route::parse(&raw, u64::MAX); }
    }
}
