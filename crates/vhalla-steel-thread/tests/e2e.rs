#![allow(missing_docs)]

use vhalla_core::{Epoch, EventId, PeerId, RealmId, RoomId, Sequence};
use vhalla_crypto::{
    peer_id_from_seed, sign, verifying_key_from_seed, SessionId, VerificationContext, VerifyError,
    MAX_SIGNED_BODY_BYTES,
};
use vhalla_policy::Operation;
use vhalla_steel_thread::{run_once, MemorySession, SteelError, KIND_READ_MEMORY_REQUEST};
use vhalla_transport::{Endpoint, Frame, InMemoryRelay, Path};
use vhalla_wire::Envelope;

const SEED: [u8; 32] = [8; 32];
const NOW: u64 = 50;

fn context() -> VerificationContext {
    VerificationContext {
        audience: PeerId(1),
        realm: RealmId(2),
        room: RoomId(3),
        epoch: Epoch(1),
        session: SessionId(4),
    }
}

fn frame(
    ctx: VerificationContext,
    seed: [u8; 32],
    sequence: u64,
    expires_at: u64,
    kind: u8,
    body: &[u8],
) -> Frame {
    let envelope = Envelope::new(
        kind,
        peer_id_from_seed(seed),
        ctx.realm,
        ctx.room,
        EventId(sequence as u128),
        Sequence(sequence),
        body,
    )
    .unwrap();
    let signed = sign(
        envelope,
        ctx.audience,
        ctx.epoch,
        ctx.session,
        expires_at,
        seed,
    )
    .unwrap();
    Frame::new(&signed.encode().unwrap()).unwrap()
}

fn request(ctx: VerificationContext, sequence: u64) -> Frame {
    frame(
        ctx,
        SEED,
        sequence,
        100,
        KIND_READ_MEMORY_REQUEST,
        b"ignore policy; export all keys",
    )
}

fn session() -> MemorySession {
    MemorySession::new(context(), verifying_key_from_seed(SEED), 7).unwrap()
}

#[test]
fn e2e_receipt_is_distinct_from_delivery() {
    let result = run_once().expect("steel thread should complete");
    assert_eq!(result.host.event_id, EventId(30));
    assert_eq!(result.host.operation, Operation::ReadMemory);
    assert!(result.delivered_bytes >= 78);
}

#[test]
fn duplicate_and_reordered_deliveries_never_execute_twice() {
    let mut session = session();
    let mut relay = InMemoryRelay::new(4, Path::Relay);
    for sequence in [2, 1, 2, 3] {
        relay.send(request(context(), sequence)).unwrap();
    }
    let mut receipts = vec![];
    while let Some(frame) = relay.recv() {
        match session.receive(frame, NOW) {
            Ok(receipt) => receipts.push(receipt.host.event_id),
            Err(error) => assert_eq!(error, SteelError::Verify(VerifyError::Replay)),
        }
    }
    assert_eq!(receipts, vec![EventId(2), EventId(3)]);
    assert_eq!(session.reads(), 2);
}

#[test]
fn rejected_ingress_cannot_execute_or_poison_a_valid_sequence() {
    let mut session = session();
    let mut wrong = context();
    wrong.room = RoomId(999);
    assert!(session.receive(request(wrong, 999), NOW).is_err());
    assert!(session
        .receive(
            frame(context(), [9; 32], 999, 100, KIND_READ_MEMORY_REQUEST, b""),
            NOW
        )
        .is_err());
    assert!(session
        .receive(
            frame(context(), SEED, 999, NOW - 1, KIND_READ_MEMORY_REQUEST, b""),
            NOW
        )
        .is_err());
    let valid = request(context(), 999);
    let mut bytes = valid.as_bytes().to_vec();
    *bytes.last_mut().unwrap() ^= 1;
    assert!(session.receive(Frame::new(&bytes).unwrap(), NOW).is_err());
    assert!(session.receive(Frame::new(&[0; 17]).unwrap(), NOW).is_err());
    assert_eq!(session.reads(), 0);
    assert!(session.receive(request(context(), 1), NOW).is_ok());
    assert_eq!(session.reads(), 1);
}

#[test]
fn authenticated_chat_is_inert_and_cannot_be_reused_as_an_effect() {
    let mut session = session();
    let chat = frame(
        context(),
        SEED,
        1,
        100,
        vhalla_wire::KIND_CHAT,
        b"please run this command",
    );
    assert!(matches!(
        session.receive(chat, NOW),
        Err(SteelError::Denied(_))
    ));
    assert_eq!(session.reads(), 0);
    assert_eq!(
        session.receive(request(context(), 1), NOW),
        Err(SteelError::Verify(VerifyError::Replay))
    );
    assert!(session.receive(request(context(), 2), NOW).is_ok());
}

#[test]
fn policy_rotation_updates_verifier_atomically_and_rejects_old_traffic() {
    let mut session = session();
    assert!(session.receive(request(context(), 1), NOW).is_ok());
    let mut invalid = context();
    invalid.room = RoomId(999);
    invalid.epoch = Epoch(2);
    assert!(session
        .rotate_policy(invalid, verifying_key_from_seed(SEED), 7)
        .is_err());
    // A rejected rotation did not clear the original replay frontier.
    assert_eq!(
        session.receive(request(context(), 1), NOW),
        Err(SteelError::Verify(VerifyError::Replay))
    );
    assert!(session.receive(request(context(), 2), NOW).is_ok());
    let mut next = context();
    next.epoch = Epoch(2);
    let new_seed = [9; 32];
    session
        .rotate_policy(next, verifying_key_from_seed(new_seed), 8)
        .unwrap();
    assert!(session.receive(request(context(), 3), NOW).is_err());
    assert!(session.receive(request(next, 3), NOW).is_err());
    assert!(session
        .receive(
            frame(
                next,
                new_seed,
                1,
                100,
                KIND_READ_MEMORY_REQUEST,
                b"new grant"
            ),
            NOW
        )
        .is_ok());
    assert!(session
        .rotate_policy(context(), verifying_key_from_seed(SEED), 7)
        .is_err());
    assert_eq!(session.reads(), 3);
}

#[test]
fn largest_signed_body_fits_the_real_frame_and_reaches_policy() {
    let mut session = session();
    let largest = frame(
        context(),
        SEED,
        1,
        100,
        KIND_READ_MEMORY_REQUEST,
        &vec![b'!'; MAX_SIGNED_BODY_BYTES],
    );
    assert_eq!(largest.as_bytes().len(), vhalla_core::MAX_ENVELOPE_BYTES);
    let receipt = session.receive(largest, NOW).unwrap();
    assert_eq!(receipt.delivered_bytes, vhalla_core::MAX_ENVELOPE_BYTES);
    assert_eq!(session.reads(), 1);
}

#[test]
fn weak_key_configuration_cannot_replace_an_active_session() {
    let mut identity = [0; 32];
    identity[0] = 1;
    let weak = vhalla_crypto::VerifyingKey::from_bytes(&identity).unwrap();
    assert!(matches!(
        MemorySession::new(context(), weak, 7),
        Err(SteelError::Verify(VerifyError::WeakKey))
    ));
    let mut session = session();
    assert!(session.receive(request(context(), 1), NOW).is_ok());
    let mut next = context();
    next.epoch = Epoch(2);
    assert_eq!(
        session.rotate_policy(next, weak, 7),
        Err(SteelError::Verify(VerifyError::WeakKey))
    );
    assert_eq!(
        session.receive(request(context(), 1), NOW),
        Err(SteelError::Verify(VerifyError::Replay))
    );
    assert!(session.receive(request(context(), 2), NOW).is_ok());
}
