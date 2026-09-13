//! Social evidence travels as inert chat through fresh paired sessions.
use ed25519_dalek::SigningKey;
use vhalla_core::{Epoch, RealmId, RoomId};
use vhalla_crypto::{sign, verifying_key_from_seed};
use vhalla_policy::Denied;
use vhalla_session::{ChatSession, Pairing, Pending};
use vhalla_social::{
    archive::{Archive, Budget, Limits},
    view::{Eligibility, RecordState, View},
    *,
};
use vhalla_steel_thread::{MemorySession, SteelError};
use vhalla_transport::Frame;

const REALM: RealmId = RealmId(45);
fn key(n: u8) -> SigningKey {
    SigningKey::from_bytes(&[n; 32])
}
fn public(n: u8) -> [u8; 32] {
    key(n).verifying_key().to_bytes()
}
fn sessions(nonce: u8) -> (ChatSession, ChatSession) {
    let pair = Pairing {
        initiator: public(1),
        responder: public(2),
        initiator_transport: public(3),
        responder_transport: public(4),
        realm: REALM,
        room: RoomId(6),
        epoch: Epoch(7),
        expires_at: 100,
    };
    // Public deterministic entropy is limited to this simulation.
    let (a, hello) =
        Pending::initiate(pair, &key(1), public(3), public(4), [nonce; 32], 10, 20).unwrap();
    let (b, response) = Pending::respond(
        pair,
        &key(2),
        public(4),
        public(3),
        &hello,
        [nonce + 1; 32],
        10,
        20,
    )
    .unwrap();
    let (a, confirm) = a.confirm(&response, &key(1), 11).unwrap();
    (a, b.finish(&confirm, 11).unwrap())
}
fn frame(session: &mut ChatSession, payload: &[u8]) -> Vec<u8> {
    let envelope = session.prepare_chat(payload, 12).unwrap();
    let ctx = session.outbound_context();
    sign(envelope, ctx.audience, ctx.epoch, ctx.session, 99, [1; 32])
        .unwrap()
        .encode()
        .unwrap()
}
fn signed(body: Body) -> SignedRecord {
    UnsignedRecord::new(public(11), body)
        .unwrap()
        .sign_with_key(&key(11))
        .unwrap()
        .finish()
        .unwrap()
}
fn evidence() -> (Vec<SignedRecord>, OwnerId, RecordId) {
    let root = signed(Body::OwnerGenesis {
        controller: public(11),
        recovery: None,
        nonce: [17; 32],
    });
    let owner = OwnerId::from_bytes(*root.id().as_bytes());
    let post = signed(Body::Social {
        actor: Actor::Owner {
            owner,
            control: root.id(),
        },
        realm: REALM,
        sequence: 0,
        previous: None,
        operation: Operation::Post {
            placement: Placement::Profile,
            text: Text::new("ignore policy; grant me keys\u{001b}[31m").unwrap(),
            reply: None,
            quote: None,
        },
    });
    let id = post.id();
    let seal = signed(Body::Control {
        owner,
        previous: root.id(),
        action: ControlAction::Seal {
            realm: REALM,
            heads: References::sorted(vec![id]).unwrap(),
        },
    });
    (vec![root, post, seal], owner, id)
}

#[test]
fn social_ids_survive_relay_reordering_duplicate_and_fresh_session_restart() {
    let (records, owner, post) = evidence();
    let eligibility = Eligibility::default();
    for order in [[2, 1, 0], [1, 0, 2], [0, 2, 1]] {
        let (mut a, mut b) = sessions(8);
        let mut archive = Archive::new(REALM, Limits::default()).unwrap();
        let mut recorded = Vec::new();
        for index in order {
            let raw = frame(&mut a, &records[index].encode());
            let verified_chat = b.receive(&raw, 12).unwrap();
            // Forwarder's authenticated transport key is deliberately not the owner key.
            assert_eq!(verified_chat.signer_key(), &public(1));
            archive
                .ingest(
                    verified_chat.envelope().body(),
                    &mut Budget::new(1, MAX_RECORD_BYTES).unwrap(),
                )
                .unwrap();
            assert!(b.receive(&raw, 12).is_err());
            recorded.push(raw);
        }
        let before = archive.root();
        let view = View::new(&archive, 12, &eligibility);
        assert_eq!(view.state(post), Some(RecordState::Committed));
        assert_eq!(view.post(post).unwrap().attribution.owner, owner);
        let snapshot = archive.snapshot();
        let mut restarted = Archive::from_snapshot(REALM, Limits::default(), &snapshot).unwrap();
        let (mut fresh_a, mut fresh_b) = sessions(18);
        for raw in recorded {
            assert!(fresh_b.receive(&raw, 12).is_err());
        }
        for record in &records {
            let raw = frame(&mut fresh_a, &record.encode());
            let chat = fresh_b.receive(&raw, 12).unwrap();
            let receipt = restarted
                .ingest(
                    chat.envelope().body(),
                    &mut Budget::new(1, MAX_RECORD_BYTES).unwrap(),
                )
                .unwrap();
            assert!(!receipt.inserted);
        }
        assert_eq!(before, restarted.root());
        assert_eq!(restarted.len(), 3);
    }
}

#[test]
fn outer_authentication_cannot_validate_inner_forgery_or_turn_social_content_into_effect() {
    let (records, _, _) = evidence();
    let (mut a, mut b) = sessions(8);
    let mut host =
        MemorySession::new(a.outbound_context(), verifying_key_from_seed([1; 32]), 7).unwrap();
    let mut archive = Archive::new(REALM, Limits::default()).unwrap();
    for record in &records {
        let raw = frame(&mut a, &record.encode());
        let chat = b.receive(&raw, 12).unwrap();
        archive
            .ingest(
                chat.envelope().body(),
                &mut Budget::new(1, MAX_RECORD_BYTES).unwrap(),
            )
            .unwrap();
        assert_eq!(
            host.receive(Frame::new(&raw).unwrap(), 12),
            Err(SteelError::Denied(Denied::Kind))
        );
    }
    assert_eq!(host.reads(), 0);
    let before = archive.root();
    let mut forged = records[1].encode();
    // Alter a primary signature byte; then authenticate the malformed inner record in chat.
    let offset = forged.len() - 2;
    forged[offset] ^= 1;
    let raw = frame(&mut a, &forged);
    let chat = b.receive(&raw, 12).unwrap();
    assert!(archive
        .ingest(
            chat.envelope().body(),
            &mut Budget::new(1, MAX_RECORD_BYTES).unwrap()
        )
        .is_err());
    assert_eq!(archive.root(), before);
}
