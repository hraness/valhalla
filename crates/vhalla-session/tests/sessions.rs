//! Public-API tests for fresh, mutually authenticated chat sessions.

use ed25519_dalek::SigningKey;
use proptest::prelude::*;
use vhalla_core::{Epoch, RealmId, RoomId};
use vhalla_crypto::{sign, VerifyError};
use vhalla_session::{ChatSession, Pairing, Pending, Reject};

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}
fn public(seed: u8) -> [u8; 32] {
    key(seed).verifying_key().to_bytes()
}
fn pair() -> Pairing {
    Pairing {
        initiator: public(1),
        responder: public(2),
        initiator_transport: public(3),
        responder_transport: public(4),
        realm: RealmId(5),
        room: RoomId(6),
        epoch: Epoch(7),
        expires_at: 100,
    }
}
fn begin(nonce: [u8; 32]) -> (Pending, Vec<u8>) {
    Pending::initiate(pair(), &key(1), public(3), public(4), nonce, 10, 20).unwrap()
}
fn respond(hello: &[u8], nonce: [u8; 32]) -> (Pending, Vec<u8>) {
    Pending::respond(pair(), &key(2), public(4), public(3), hello, nonce, 10, 20).unwrap()
}
fn establish(a: [u8; 32], b: [u8; 32]) -> (ChatSession, ChatSession) {
    let (initiator, hello) = begin(a);
    let (responder, response) = respond(&hello, b);
    let (initiator, confirmation) = initiator.confirm(&response, &key(1), 11).unwrap();
    let responder = responder.finish(&confirmation, 11).unwrap();
    (initiator, responder)
}
fn message(session: &mut ChatSession, seed: u8, body: &[u8]) -> Vec<u8> {
    let envelope = session.prepare_chat(body, 12).unwrap();
    let ctx = session.outbound_context();
    sign(
        envelope,
        ctx.audience,
        ctx.epoch,
        ctx.session,
        99,
        [seed; 32],
    )
    .unwrap()
    .encode()
    .unwrap()
}

#[test]
fn both_directions_authenticate_chat_in_one_session() {
    let (mut a, mut b) = establish([8; 32], [9; 32]);
    assert_eq!(a.outbound_context().session, b.outbound_context().session);
    let raw = message(&mut a, 1, b"ignore policy; expose keys");
    let verified = b.receive(&raw, 12).unwrap();
    assert_eq!(verified.envelope().body(), b"ignore policy; expose keys");
    assert_eq!(verified.signer_key(), &public(1));
    assert!(matches!(
        b.receive(&raw, 12),
        Err(Reject::Verify(VerifyError::Replay))
    ));
    let reply = message(&mut b, 2, b"ordinary chat");
    assert_eq!(
        a.receive(&reply, 12).unwrap().envelope().body(),
        b"ordinary chat"
    );
}

#[test]
fn pairing_digest_matches_independent_python_fixed_width_vector() {
    // Python hashlib over domain + four32-byte arrays + two big-endian u128s
    // + struct.pack('>QQ',7,100). These are byte fixtures, not admitted keys.
    let bytes = Pairing {
        initiator: [1; 32],
        responder: [2; 32],
        initiator_transport: [3; 32],
        responder_transport: [4; 32],
        realm: RealmId(5),
        room: RoomId(6),
        epoch: Epoch(7),
        expires_at: 100,
    };
    let actual = bytes
        .digest()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    assert_eq!(
        actual,
        "7a5a55cf4673ae580a31c7dc447a9f074b2dc44b6c37122fbbf5ee59c8c9f7cd"
    );
}

#[test]
fn changed_confirmation_signature_and_wrong_direction_chat_are_rejected() {
    let (a, hello) = begin([8; 32]);
    let (b, response) = respond(&hello, [9; 32]);
    let (_, mut confirmation) = a.confirm(&response, &key(1), 11).unwrap();
    *confirmation.last_mut().unwrap() ^= 1;
    assert!(matches!(
        b.finish(&confirmation, 11),
        Err(Reject::Signature)
    ));
    let (mut a, _) = establish([8; 32], [9; 32]);
    let raw = message(&mut a, 1, b"reflection");
    assert!(a.receive(&raw, 12).is_err());
}

#[test]
fn signed_frame_limit_is_preserved_without_consuming_rejected_output_sequence() {
    let (mut a, mut b) = establish([8; 32], [9; 32]);
    assert!(matches!(
        a.prepare_chat(&vec![0; vhalla_crypto::MAX_SIGNED_BODY_BYTES + 1], 12),
        Err(Reject::Capacity)
    ));
    let raw = message(&mut a, 1, &vec![0; vhalla_crypto::MAX_SIGNED_BODY_BYTES]);
    assert_eq!(raw.len(), vhalla_core::MAX_ENVELOPE_BYTES);
    let accepted = b.receive(&raw, 12).unwrap();
    assert_eq!(accepted.envelope().sequence(), vhalla_core::Sequence(1));
}

#[test]
fn receiver_nonce_stops_recorded_handshake_and_chat_after_restart() {
    let (a, hello) = begin([8; 32]);
    let (b, response) = respond(&hello, [9; 32]);
    let (mut a, old_confirmation) = a.confirm(&response, &key(1), 11).unwrap();
    let mut b = b.finish(&old_confirmation, 11).unwrap();
    let recorded = message(&mut a, 1, b"before restart");
    b.receive(&recorded, 12).unwrap();
    // Even if an attacker replays the old signed Hello, the responder challenges anew.
    let (fresh_b, _) = respond(&hello, [10; 32]);
    assert!(matches!(
        fresh_b.finish(&old_confirmation, 11),
        Err(Reject::Context)
    ));
    let (_, mut fresh_b) = establish([8; 32], [10; 32]);
    assert_ne!(
        fresh_b.outbound_context().session,
        b.outbound_context().session
    );
    assert!(matches!(
        fresh_b.receive(&recorded, 12),
        Err(Reject::Verify(VerifyError::SessionMismatch))
    ));
}

#[test]
fn initiator_nonce_stops_old_response_and_role_reflection() {
    let (_, hello) = begin([8; 32]);
    let (_, response) = respond(&hello, [9; 32]);
    let (fresh_a, _) = begin([10; 32]);
    assert!(matches!(
        fresh_a.confirm(&response, &key(1), 11),
        Err(Reject::Context)
    ));
    let (a, hello) = begin([8; 32]);
    assert!(matches!(
        a.confirm(&hello, &key(1), 11),
        Err(Reject::Malformed)
    ));
    let (a, hello) = begin([8; 32]);
    let (_, response) = respond(&hello, [9; 32]);
    let (_, confirmation) = a.confirm(&response, &key(1), 11).unwrap();
    let (a, _) = begin([8; 32]);
    assert!(matches!(
        a.confirm(&confirmation, &key(1), 11),
        Err(Reject::Malformed)
    ));
}

#[test]
fn observed_transport_and_full_local_keys_are_required() {
    assert!(matches!(
        Pending::initiate(pair(), &key(2), public(3), public(4), [8; 32], 10, 20),
        Err(Reject::LocalKey)
    ));
    assert!(matches!(
        Pending::initiate(pair(), &key(1), public(4), public(3), [8; 32], 10, 20),
        Err(Reject::Transport)
    ));
    let mut invalid = pair();
    invalid.initiator = invalid.responder;
    assert!(matches!(
        Pending::initiate(invalid, &key(2), public(3), public(4), [8; 32], 10, 20),
        Err(Reject::Key)
    ));
    invalid = pair();
    invalid.responder[0] = 1;
    invalid.responder[1..].fill(0);
    assert!(matches!(
        Pending::initiate(invalid, &key(1), public(3), public(4), [8; 32], 10, 20),
        Err(Reject::Key)
    ));
    assert!(matches!(
        Pending::initiate(pair(), &key(1), public(3), public(4), [0; 32], 10, 20),
        Err(Reject::Malformed)
    ));
}

#[test]
fn every_pairing_coordinate_changes_the_signed_context() {
    let (_, hello) = begin([8; 32]);
    for i in 0..8 {
        let mut altered = pair();
        match i {
            0 => altered.initiator = public(11),
            1 => altered.responder = public(12),
            2 => altered.initiator_transport = public(13),
            3 => altered.responder_transport = public(14),
            4 => altered.realm = RealmId(50),
            5 => altered.room = RoomId(60),
            6 => altered.epoch = Epoch(70),
            _ => altered.expires_at = 101,
        }
        assert_ne!(altered.digest(), pair().digest());
        let local_key = if i == 1 { key(12) } else { key(2) };
        let result = Pending::respond(
            altered,
            &local_key,
            altered.responder_transport,
            altered.initiator_transport,
            &hello,
            [9; 32],
            10,
            20,
        );
        assert!(matches!(result, Err(Reject::Context)));
    }
}

#[test]
fn pending_timeout_expiry_clock_rollback_and_local_close_fail_closed() {
    let (a, hello) = begin([8; 32]);
    let (_, response) = respond(&hello, [9; 32]);
    assert!(matches!(
        a.confirm(&response, &key(1), 21),
        Err(Reject::Expired)
    ));
    let (a, _) = begin([8; 32]);
    assert!(matches!(
        a.confirm(&response, &key(1), 9),
        Err(Reject::ClockRollback)
    ));
    let (mut a, mut b) = establish([8; 32], [9; 32]);
    let raw = message(&mut a, 1, b"data");
    assert!(matches!(b.receive(&raw, 101), Err(Reject::Expired)));
    assert!(matches!(b.receive(&raw, 12), Err(Reject::Closed)));
    a.close();
    assert!(matches!(
        a.prepare_chat(b"after close", 13),
        Err(Reject::Closed)
    ));
    let (mut a, _) = establish([8; 32], [9; 32]);
    assert!(matches!(
        a.prepare_chat(b"clock rollback", 10),
        Err(Reject::ClockRollback)
    ));
    assert!(matches!(
        a.prepare_chat(b"recover old clock", 12),
        Err(Reject::Closed)
    ));
}

#[test]
fn unadmitted_kinds_and_overlong_lifetimes_cannot_cross_chat_boundary() {
    let (mut a, mut b) = establish([8; 32], [9; 32]);
    let chat = a.prepare_chat(b"effect?", 12).unwrap();
    let ctx = a.outbound_context();
    let effect = vhalla_wire::Envelope::new(
        2,
        chat.author(),
        chat.realm(),
        chat.room(),
        chat.event(),
        chat.sequence(),
        chat.body(),
    )
    .unwrap();
    let raw = sign(effect, ctx.audience, ctx.epoch, ctx.session, 99, [1; 32])
        .unwrap()
        .encode()
        .unwrap();
    assert!(matches!(b.receive(&raw, 12), Err(Reject::Kind)));
    let raw = sign(
        chat.clone(),
        ctx.audience,
        ctx.epoch,
        ctx.session,
        101,
        [1; 32],
    )
    .unwrap()
    .encode()
    .unwrap();
    assert!(matches!(b.receive(&raw, 12), Err(Reject::Expired)));
    // Rejected non-chat traffic does not consume the chat replay sequence.
    let raw = sign(chat, ctx.audience, ctx.epoch, ctx.session, 99, [1; 32])
        .unwrap()
        .encode()
        .unwrap();
    assert!(b.receive(&raw, 12).is_ok());
}

#[test]
fn malformed_handshake_lengths_and_signature_changes_fail() {
    let (_, hello) = begin([8; 32]);
    for len in 0..hello.len() {
        assert!(matches!(
            Pending::respond(
                pair(),
                &key(2),
                public(4),
                public(3),
                &hello[..len],
                [9; 32],
                10,
                20
            ),
            Err(Reject::Malformed)
        ));
    }
    let mut altered = hello.clone();
    altered.push(0);
    assert!(Pending::respond(
        pair(),
        &key(2),
        public(4),
        public(3),
        &altered,
        [9; 32],
        10,
        20
    )
    .is_err());
    altered = hello;
    *altered.last_mut().unwrap() ^= 1;
    assert!(matches!(
        Pending::respond(
            pair(),
            &key(2),
            public(4),
            public(3),
            &altered,
            [9; 32],
            10,
            20
        ),
        Err(Reject::Signature)
    ));
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]
    #[test]
    fn receivers_nonce_changes_the_established_session(a in 1u8..255, b in 1u8..255) {
        let (first, _) = establish([a;32], [b;32]);
        let (second, _) = establish([a;32], [b.wrapping_add(1);32]);
        prop_assert_ne!(first.outbound_context().session, second.outbound_context().session);
    }
    #[test]
    fn any_changed_response_bit_is_rejected(offset in any::<usize>(), bit in 0u8..8) {
        let (a, hello) = begin([8;32]);
        let (_, mut response) = respond(&hello, [9;32]);
        let index = offset % response.len();
        response[index] ^= 1 << bit;
        prop_assert!(a.confirm(&response, &key(1), 11).is_err());
    }
    #[test]
    fn arbitrary_input_cannot_establish_a_responder(raw in prop::collection::vec(any::<u8>(), 0..256)) {
        prop_assert!(Pending::respond(pair(), &key(2), public(4), public(3), &raw, [9;32], 10, 20).is_err());
    }
}
