//! Adversarial delivery scheduling under Hegel's interleaved draw model.
//!
//! This is the `adversarial_delivery_matches_effect_count_model` state machine
//! from `e2e.rs`, ported to Hegel's draw-inside-the-loop style: each hostile
//! delivery is drawn while the trace executes rather than materialized as a
//! schedule up front.

use hegel::generators as gs;
use hegel::TestCase;
use vhalla_core::{Epoch, EventId, PeerId, RealmId, RoomId, Sequence};
use vhalla_crypto::{
    peer_id_from_seed, sign, verifying_key_from_seed, SessionId, VerificationContext,
};
use vhalla_steel_thread::{MemorySession, KIND_READ_MEMORY_REQUEST};
use vhalla_transport::Frame;
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

fn session() -> MemorySession {
    MemorySession::new(context(), verifying_key_from_seed(SEED), 7).unwrap()
}

#[hegel::test(test_cases = 32)]
fn adversarial_delivery_matches_effect_count_model(tc: TestCase) {
    let mut session = session();
    let mut high_water = 0;
    let mut expected_reads = 0;
    let steps = tc.draw(gs::integers::<usize>().max_value(23));
    for _ in 0..steps {
        let sequence = tc.draw(gs::integers::<u64>().min_value(1).max_value(15));
        let expired = tc.draw(gs::booleans());
        let tampered = tc.draw(gs::booleans());
        let wrong_room = tc.draw(gs::booleans());
        let mut ctx = context();
        if wrong_room {
            ctx.room = RoomId(999);
        }
        let message = frame(
            ctx,
            SEED,
            sequence,
            if expired { NOW - 1 } else { NOW + 1 },
            KIND_READ_MEMORY_REQUEST,
            b"hostile remote text",
        );
        let mut bytes = message.as_bytes().to_vec();
        if tampered {
            *bytes.last_mut().unwrap() ^= 1;
        }
        let expected = !expired && !tampered && !wrong_room && sequence > high_water;
        let result = session.receive(Frame::new(&bytes).unwrap(), NOW);
        assert_eq!(result.is_ok(), expected);
        if expected {
            high_water = sequence;
            expected_reads += 1;
        }
        assert_eq!(session.reads(), expected_reads);
    }
}
