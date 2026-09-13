#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Fresh chat sessions for two explicitly paired peers.
//!
//! Pairing is trusted local configuration, not a self-authorizing invitation.
//! The adapter supplies keys observed on an authenticated transport and fresh
//! nonces from OS/browser entropy. This crate has no network, clock, entropy,
//! storage, policy, or host effects. A new connection must complete a new
//! handshake, never reconstruct a replay window from a static invitation.

extern crate alloc;

mod invitation;

pub use invitation::{Invitation, InvitationClaims, InvitationError, INVITATION_BYTES};

use alloc::vec::Vec;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use vhalla_core::{Epoch, EventId, RealmId, RoomId, Sequence};
use vhalla_crypto::{
    peer_id_from_key, ReplayWindow, SessionId, SignedEnvelope, VerificationContext,
    VerifiedEnvelope, VerifyError,
};
use vhalla_wire::{Envelope, KIND_CHAT};

const MAGIC: &[u8; 4] = b"VHS1";
const HELLO: u8 = 1;
const RESPONSE: u8 = 2;
const CONFIRM: u8 = 3;
const HELLO_BYTES: usize = 133;
/// Maximum canonical handshake packet length; checked before allocation.
pub const MAX_HANDSHAKE_BYTES: usize = 165;
const DOMAIN: &[u8] = b"vhalla/paired-chat/handshake/v1";

/// Which peer initiates the three-message handshake.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Role {
    /// Sends Hello and final confirmation.
    Initiator,
    /// Challenges Hello with its own fresh nonce.
    Responder,
}

/// Locally pinned pair and bounded chat lifetime. This is configuration, not
/// evidence. Both adapters must agree on every field and on peer roles.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Pairing {
    /// Full application key of the initiator.
    pub initiator: [u8; 32],
    /// Full application key of the responder.
    pub responder: [u8; 32],
    /// Full authenticated transport key of the initiator.
    pub initiator_transport: [u8; 32],
    /// Full authenticated transport key of the responder.
    pub responder_transport: [u8; 32],
    /// Realm namespace.
    pub realm: RealmId,
    /// Room namespace.
    pub room: RoomId,
    /// Current locally admitted membership epoch.
    pub epoch: Epoch,
    /// Inclusive maximum lifetime in the adapter's trusted clock units.
    pub expires_at: u64,
}

/// Bounded protocol failures. Rejected handshake state is consumed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Reject {
    /// Framing, version, packet kind, length or nonce is invalid.
    Malformed,
    /// A full application or transport key is invalid/weak, or peers coincide.
    Key,
    /// Local signing key differs from its configured role.
    LocalKey,
    /// Observed transport keys differ from the explicit pairing.
    Transport,
    /// Pair digest or expected handshake nonces differ.
    Context,
    /// Strict signature verification failed.
    Signature,
    /// Pair lifetime or bounded pending-handshake deadline elapsed.
    Expired,
    /// Time moved backwards relative to a previously accepted local clock read.
    ClockRollback,
    /// Session has been revoked locally or expired and cannot be revived.
    Closed,
    /// Only chat kind is admitted by this session.
    Kind,
    /// Signed chat verification failed.
    Verify(VerifyError),
    /// Outbound sequence cannot advance or body exceeds the signed frame bound.
    Capacity,
}

impl Pairing {
    fn validate(&self) -> Result<(), Reject> {
        if self.initiator == self.responder {
            return Err(Reject::Key);
        }
        for bytes in [
            self.initiator,
            self.responder,
            self.initiator_transport,
            self.responder_transport,
        ] {
            checked_key(bytes)?;
        }
        Ok(())
    }

    /// Canonical digest of the explicit local pairing, including the chat-only
    /// protocol and both application/transport identities. It is not a signature.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"vhalla/paired-chat/config/v1");
        hash.update(self.initiator);
        hash.update(self.responder);
        hash.update(self.initiator_transport);
        hash.update(self.responder_transport);
        hash.update(self.realm.0.to_be_bytes());
        hash.update(self.room.0.to_be_bytes());
        hash.update(self.epoch.0.to_be_bytes());
        hash.update(self.expires_at.to_be_bytes());
        hash.finalize().into()
    }

    fn local(&self, role: Role) -> [u8; 32] {
        match role {
            Role::Initiator => self.initiator,
            Role::Responder => self.responder,
        }
    }

    fn remote(&self, role: Role) -> [u8; 32] {
        match role {
            Role::Initiator => self.responder,
            Role::Responder => self.initiator,
        }
    }

    fn check_local(
        &self,
        role: Role,
        key: &SigningKey,
        observed_local: [u8; 32],
        observed_remote: [u8; 32],
    ) -> Result<(), Reject> {
        self.validate()?;
        if key.verifying_key().to_bytes() != self.local(role) {
            return Err(Reject::LocalKey);
        }
        let expected = match role {
            Role::Initiator => (self.initiator_transport, self.responder_transport),
            Role::Responder => (self.responder_transport, self.initiator_transport),
        };
        if (observed_local, observed_remote) != expected {
            return Err(Reject::Transport);
        }
        Ok(())
    }
}

fn checked_key(bytes: [u8; 32]) -> Result<VerifyingKey, Reject> {
    let key = VerifyingKey::from_bytes(&bytes).map_err(|_| Reject::Key)?;
    if key.is_weak() {
        return Err(Reject::Key);
    }
    Ok(key)
}

fn fresh_nonce(nonce: &[u8; 32]) -> Result<(), Reject> {
    // Only catches a broken/default source, not reused or predictable entropy.
    if *nonce == [0; 32] {
        return Err(Reject::Malformed);
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct Packet {
    kind: u8,
    pairing: [u8; 32],
    initiator_nonce: [u8; 32],
    responder_nonce: [u8; 32],
    signature: [u8; 64],
}

impl Packet {
    fn unsigned(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(MAX_HANDSHAKE_BYTES - 64);
        out.extend_from_slice(MAGIC);
        out.push(self.kind);
        out.extend_from_slice(&self.pairing);
        out.extend_from_slice(&self.initiator_nonce);
        if self.kind != HELLO {
            out.extend_from_slice(&self.responder_nonce);
        }
        out
    }

    fn transcript(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(DOMAIN.len() + MAX_HANDSHAKE_BYTES - 64);
        out.extend_from_slice(DOMAIN);
        out.extend_from_slice(&self.unsigned());
        out
    }

    fn signed(mut self, key: &SigningKey) -> Vec<u8> {
        self.signature = key.sign(&self.transcript()).to_bytes();
        let mut out = self.unsigned();
        out.extend_from_slice(&self.signature);
        out
    }

    fn decode(raw: &[u8], kind: u8) -> Result<Self, Reject> {
        let length = if kind == HELLO {
            HELLO_BYTES
        } else {
            MAX_HANDSHAKE_BYTES
        };
        if raw.len() != length || &raw[..4] != MAGIC || raw[4] != kind {
            return Err(Reject::Malformed);
        }
        let initiator_nonce = raw[37..69].try_into().map_err(|_| Reject::Malformed)?;
        let responder_nonce = if kind == HELLO {
            [0; 32]
        } else {
            raw[69..101].try_into().map_err(|_| Reject::Malformed)?
        };
        fresh_nonce(&initiator_nonce)?;
        if kind != HELLO {
            fresh_nonce(&responder_nonce)?;
        }
        Ok(Self {
            kind,
            pairing: raw[5..37].try_into().map_err(|_| Reject::Malformed)?,
            initiator_nonce,
            responder_nonce,
            signature: raw[length - 64..]
                .try_into()
                .map_err(|_| Reject::Malformed)?,
        })
    }

    fn verify(&self, key: [u8; 32]) -> Result<(), Reject> {
        checked_key(key)?
            .verify_strict(&self.transcript(), &Signature::from_bytes(&self.signature))
            .map_err(|_| Reject::Signature)
    }

    fn session_id(&self) -> SessionId {
        let mut hash = Sha256::new();
        hash.update(b"vhalla/paired-chat/session/v1");
        hash.update(self.pairing);
        hash.update(self.initiator_nonce);
        hash.update(self.responder_nonce);
        let digest = hash.finalize();
        SessionId(u128::from_be_bytes(
            digest[..16].try_into().expect("sixteen bytes"),
        ))
    }
}

/// Pending handshake; neither cloneable nor deserializable. The caller owns a
/// bounded number of these and must use fresh entropy for every construction.
pub struct Pending {
    pairing: Pairing,
    role: Role,
    packet: Packet,
    started_at: u64,
    deadline: u64,
}

impl Pending {
    /// Start as initiator on an already authenticated, explicitly pinned
    /// transport. `deadline` uses the same trusted clock units as `now`.
    #[allow(clippy::too_many_arguments)]
    pub fn initiate(
        pairing: Pairing,
        key: &SigningKey,
        observed_local: [u8; 32],
        observed_remote: [u8; 32],
        nonce: [u8; 32],
        now: u64,
        deadline: u64,
    ) -> Result<(Self, Vec<u8>), Reject> {
        pairing.check_local(Role::Initiator, key, observed_local, observed_remote)?;
        let deadline = check_deadline(pairing, now, deadline)?;
        fresh_nonce(&nonce)?;
        let packet = Packet {
            kind: HELLO,
            pairing: pairing.digest(),
            initiator_nonce: nonce,
            responder_nonce: [0; 32],
            signature: [0; 64],
        };
        let bytes = packet.signed(key);
        Ok((
            Self {
                pairing,
                role: Role::Initiator,
                packet,
                started_at: now,
                deadline,
            },
            bytes,
        ))
    }

    /// Verify Hello as responder and bind it to a fresh receiver nonce. Replaying
    /// an old Hello cannot complete this new challenge with an old confirmation.
    #[allow(clippy::too_many_arguments)]
    pub fn respond(
        pairing: Pairing,
        key: &SigningKey,
        observed_local: [u8; 32],
        observed_remote: [u8; 32],
        hello: &[u8],
        nonce: [u8; 32],
        now: u64,
        deadline: u64,
    ) -> Result<(Self, Vec<u8>), Reject> {
        pairing.check_local(Role::Responder, key, observed_local, observed_remote)?;
        let deadline = check_deadline(pairing, now, deadline)?;
        fresh_nonce(&nonce)?;
        let mut packet = Packet::decode(hello, HELLO)?;
        if packet.pairing != pairing.digest() {
            return Err(Reject::Context);
        }
        packet.verify(pairing.initiator)?;
        packet.kind = RESPONSE;
        packet.responder_nonce = nonce;
        let bytes = packet.signed(key);
        Ok((
            Self {
                pairing,
                role: Role::Responder,
                packet,
                started_at: now,
                deadline,
            },
            bytes,
        ))
    }

    /// Consume the initiator challenge, authenticate the response and return a
    /// final signed confirmation. The adapter must deliver confirmation before
    /// sending chat; local establishment is not proof of remote receipt.
    pub fn confirm(
        self,
        response: &[u8],
        key: &SigningKey,
        now: u64,
    ) -> Result<(ChatSession, Vec<u8>), Reject> {
        self.check_time(now)?;
        if self.role != Role::Initiator || key.verifying_key().to_bytes() != self.pairing.initiator
        {
            return Err(Reject::LocalKey);
        }
        let mut packet = Packet::decode(response, RESPONSE)?;
        if packet.pairing != self.packet.pairing
            || packet.initiator_nonce != self.packet.initiator_nonce
        {
            return Err(Reject::Context);
        }
        packet.verify(self.pairing.responder)?;
        packet.kind = CONFIRM;
        let confirmation = packet.signed(key);
        Ok((
            ChatSession::establish(self.pairing, self.role, packet.session_id(), now)?,
            confirmation,
        ))
    }

    /// Consume the responder challenge only after the initiator signs both
    /// nonces. Old confirmations cannot establish a new receiver session.
    pub fn finish(self, confirmation: &[u8], now: u64) -> Result<ChatSession, Reject> {
        self.check_time(now)?;
        if self.role != Role::Responder {
            return Err(Reject::Context);
        }
        let packet = Packet::decode(confirmation, CONFIRM)?;
        if packet.pairing != self.packet.pairing
            || packet.initiator_nonce != self.packet.initiator_nonce
            || packet.responder_nonce != self.packet.responder_nonce
        {
            return Err(Reject::Context);
        }
        packet.verify(self.pairing.initiator)?;
        ChatSession::establish(self.pairing, self.role, packet.session_id(), now)
    }

    fn check_time(&self, now: u64) -> Result<(), Reject> {
        if now < self.started_at {
            return Err(Reject::ClockRollback);
        }
        if now > self.deadline {
            return Err(Reject::Expired);
        }
        Ok(())
    }
}

fn check_deadline(pairing: Pairing, now: u64, deadline: u64) -> Result<u64, Reject> {
    if now >= deadline || now > pairing.expires_at {
        return Err(Reject::Expired);
    }
    Ok(deadline.min(pairing.expires_at))
}

/// Move-only authenticated session admitting chat data exclusively.
///
/// ```compile_fail
/// use vhalla_session::ChatSession;
/// fn duplicate(session: ChatSession) { let _copy = session.clone(); }
/// ```
pub struct ChatSession {
    pairing: Pairing,
    peer: VerifyingKey,
    inbound: ReplayWindow,
    outbound: VerificationContext,
    next_sequence: u64,
    last_now: u64,
    closed: bool,
}

impl ChatSession {
    fn establish(
        pairing: Pairing,
        role: Role,
        session: SessionId,
        now: u64,
    ) -> Result<Self, Reject> {
        let local = checked_key(pairing.local(role))?;
        let peer = checked_key(pairing.remote(role))?;
        let context = VerificationContext {
            audience: peer_id_from_key(&local),
            realm: pairing.realm,
            room: pairing.room,
            epoch: pairing.epoch,
            session,
        };
        Ok(Self {
            pairing,
            peer,
            inbound: ReplayWindow::new(context, 1).map_err(Reject::Verify)?,
            outbound: VerificationContext {
                audience: peer_id_from_key(&peer),
                ..context
            },
            next_sequence: 1,
            last_now: now,
            closed: false,
        })
    }

    /// Context for signing an outbound envelope prepared by this session.
    #[must_use]
    pub fn outbound_context(&self) -> VerificationContext {
        self.outbound
    }

    /// Produce bounded chat data for the local key custodian to sign. Reserving
    /// a sequence is irreversible; failed signing may leave a safe sequence gap.
    pub fn prepare_chat(&mut self, body: &[u8], now: u64) -> Result<Envelope, Reject> {
        self.check_live(now)?;
        if body.len() > vhalla_crypto::MAX_SIGNED_BODY_BYTES {
            return Err(Reject::Capacity);
        }
        let sequence = self.next_sequence;
        let next = sequence.checked_add(1).ok_or(Reject::Capacity)?;
        // Context+sequence makes IDs deterministic and directional within this session.
        let mut hash = Sha256::new();
        hash.update(b"vhalla/paired-chat/event/v1");
        hash.update(self.outbound.session.0.to_be_bytes());
        hash.update(self.inbound.context().audience.0.to_be_bytes());
        hash.update(sequence.to_be_bytes());
        let digest = hash.finalize();
        let event = EventId(u128::from_be_bytes(
            digest[..16].try_into().expect("sixteen bytes"),
        ));
        let envelope = Envelope::chat(
            self.inbound.context().audience,
            self.pairing.realm,
            self.pairing.room,
            event,
            Sequence(sequence),
            body,
        )
        .ok_or(Reject::Capacity)?;
        self.next_sequence = next;
        Ok(envelope)
    }

    /// Authenticate bounded signed bytes and return inert chat evidence. No
    /// policy or host-effect API is imported or reachable through this crate.
    pub fn receive(&mut self, raw: &[u8], now: u64) -> Result<VerifiedEnvelope, Reject> {
        self.check_live(now)?;
        let signed = SignedEnvelope::decode(raw).map_err(|_| Reject::Malformed)?;
        if signed.envelope.kind() != KIND_CHAT {
            return Err(Reject::Kind);
        }
        if signed.expires_at > self.pairing.expires_at {
            return Err(Reject::Expired);
        }
        self.inbound
            .verify_and_accept(signed, &self.peer, now)
            .map_err(Reject::Verify)
    }

    /// Revoke locally. Closing is permanent for this session; resumption needs
    /// a newly authorized pairing and fresh handshake, not a cleared window.
    pub fn close(&mut self) {
        self.closed = true;
    }

    fn check_live(&mut self, now: u64) -> Result<(), Reject> {
        if self.closed {
            return Err(Reject::Closed);
        }
        if now < self.last_now {
            self.close();
            return Err(Reject::ClockRollback);
        }
        if now > self.pairing.expires_at {
            self.close();
            return Err(Reject::Expired);
        }
        self.last_now = now;
        Ok(())
    }
}
