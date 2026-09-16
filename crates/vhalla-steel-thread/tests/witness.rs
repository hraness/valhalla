//! Gate 5: a witness frame crosses the transport replay window into the
//! witness verifier and never moves a host effect.

use std::fs;
use std::path::Path;

use ed25519_dalek::SigningKey;
use vhalla_botcaptcha::challenge::{
    ChallengeContext, ChallengeIssuer, Purpose, VerifiedChallenge, WitnessError,
};
use vhalla_botcaptcha::response::respond;
use vhalla_core::{Epoch, EventId, PeerId, RealmId, RoomId, Sequence};
use vhalla_crypto::{
    peer_id_from_seed, sign, verifying_key_from_seed, SessionId, VerificationContext, VerifyError,
};
use vhalla_policy::Denied;
use vhalla_steel_thread::{
    MemorySession, SteelError, WitnessSession, KIND_READ_MEMORY_REQUEST, KIND_WITNESS_RESPONSE,
};
use vhalla_transport::Frame;
use vhalla_wire::Envelope;
use vhalla_witness::codec;
use vhalla_witness::manifest::ValidManifest;
use vhalla_witness::platform::WorkAllowance;
use vhalla_witness::vectors::parse;

const SUBJECT_SEED: [u8; 32] = [8; 32];
const ISSUER_SEED: [u8; 32] = [3; 32];
const NOW: u64 = 1_000;

fn context() -> VerificationContext {
    VerificationContext {
        audience: PeerId(1),
        realm: RealmId(2),
        room: RoomId(3),
        epoch: Epoch(1),
        session: SessionId(4),
    }
}

fn frame(seed: [u8; 32], sequence: u64, kind: u8, body: &[u8]) -> Frame {
    let ctx = context();
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
        NOW + 100,
        seed,
    )
    .unwrap();
    Frame::new(&signed.encode().unwrap()).unwrap()
}

struct Setup {
    session: WitnessSession,
    response: Vec<u8>,
}

fn setup() -> Setup {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../vhalla-witness/tests/vectors/fixture-opening-normal.txt");
    let vector = parse(&fs::read_to_string(path).unwrap()).unwrap();
    let manifest =
        ValidManifest::validate(codec::decode_manifest(&vector.manifest).unwrap()).unwrap();
    let candidate = codec::decode_candidate(&vector.assignment).unwrap();
    let allowance = WorkAllowance {
        max_total: manifest.fuel_total(),
    };
    let subject = SigningKey::from_bytes(&SUBJECT_SEED);
    let issuer = ChallengeIssuer::from_seed(ISSUER_SEED);
    let challenge = issuer
        .issue(
            [42; 32],
            NOW,
            600,
            subject.verifying_key().to_bytes(),
            RealmId(2),
            RoomId(3),
            Purpose::RateLimitRelief,
            manifest.hash(),
            manifest.contract(),
        )
        .unwrap();
    let expected = ChallengeContext {
        issuer_key: issuer.verifying_key(),
        subject_key: subject.verifying_key().to_bytes(),
        realm: RealmId(2),
        room: RoomId(3),
        purpose: Purpose::RateLimitRelief,
    };
    let verified = VerifiedChallenge::verify(challenge.clone(), expected, NOW - 1, NOW).unwrap();
    let response = respond(&verified, &manifest, candidate, allowance, &subject)
        .unwrap()
        .encode();
    let session = WitnessSession::new(
        context(),
        verifying_key_from_seed(SUBJECT_SEED),
        challenge,
        manifest,
        allowance,
        NOW - 1,
    )
    .unwrap();
    Setup { session, response }
}

#[test]
fn a_witness_frame_is_admitted_once_through_both_windows() {
    let Setup {
        mut session,
        response,
    } = setup();
    let witness = session
        .receive_witness(
            frame(SUBJECT_SEED, 1, KIND_WITNESS_RESPONSE, &response),
            NOW + 1,
        )
        .unwrap();
    assert!(witness.receipt().useful() > 0);
    assert_eq!(session.open_challenges(), 1);
    // The same frame again: the transport replay window refuses it first.
    assert_eq!(
        session
            .receive_witness(
                frame(SUBJECT_SEED, 1, KIND_WITNESS_RESPONSE, &response),
                NOW + 2
            )
            .err(),
        Some(SteelError::Verify(VerifyError::Replay))
    );
    // A fresh envelope carrying the same body: the one-use window refuses it.
    assert_eq!(
        session
            .receive_witness(
                frame(SUBJECT_SEED, 2, KIND_WITNESS_RESPONSE, &response),
                NOW + 3
            )
            .err(),
        Some(SteelError::Witness(WitnessError::Replay))
    );
}

#[test]
fn only_the_subject_and_only_the_witness_kind_reach_the_verifier() {
    let Setup {
        mut session,
        response,
    } = setup();
    assert_eq!(
        session
            .receive_witness(frame([9; 32], 1, KIND_WITNESS_RESPONSE, &response), NOW + 1)
            .err(),
        Some(SteelError::Verify(VerifyError::AuthorMismatch))
    );
    assert_eq!(
        session
            .receive_witness(
                frame(SUBJECT_SEED, 1, KIND_READ_MEMORY_REQUEST, &response),
                NOW + 1
            )
            .err(),
        Some(SteelError::Denied(Denied::Kind))
    );
    let mut tampered = response.clone();
    tampered[40] ^= 1;
    assert!(matches!(
        session
            .receive_witness(
                frame(SUBJECT_SEED, 2, KIND_WITNESS_RESPONSE, &tampered),
                NOW + 1
            )
            .err(),
        Some(SteelError::Witness(_))
    ));
    assert_eq!(session.open_challenges(), 0);
    assert!(session
        .receive_witness(
            frame(SUBJECT_SEED, 3, KIND_WITNESS_RESPONSE, &response),
            NOW + 1
        )
        .is_ok());
}

#[test]
fn a_witness_frame_never_moves_a_host_effect() {
    let Setup { response, .. } = setup();
    let mut memory =
        MemorySession::new(context(), verifying_key_from_seed(SUBJECT_SEED), 7).unwrap();
    assert_eq!(
        memory
            .receive(
                frame(SUBJECT_SEED, 1, KIND_WITNESS_RESPONSE, &response),
                NOW + 1
            )
            .err(),
        Some(SteelError::Denied(Denied::Kind))
    );
    assert_eq!(memory.reads(), 0);
    // The subject cannot relabel the same body as a read request either: the
    // kind is inside the signed transcript, and a request body is inert data.
    let relabeled = frame(SUBJECT_SEED, 2, KIND_READ_MEMORY_REQUEST, &response);
    let outcome = memory.receive(relabeled, NOW + 1);
    assert!(
        outcome.is_ok(),
        "a read request with an opaque body is the ordinary path"
    );
    assert_eq!(
        memory.reads(),
        1,
        "and it moved exactly one read, not a witness effect"
    );
}

#[test]
fn a_session_cannot_bind_a_key_the_challenge_did_not_name() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../vhalla-witness/tests/vectors/fixture-opening-normal.txt");
    let vector = parse(&fs::read_to_string(path).unwrap()).unwrap();
    let manifest =
        ValidManifest::validate(codec::decode_manifest(&vector.manifest).unwrap()).unwrap();
    let subject = SigningKey::from_bytes(&SUBJECT_SEED);
    let challenge = ChallengeIssuer::from_seed(ISSUER_SEED)
        .issue(
            [1; 32],
            NOW,
            600,
            subject.verifying_key().to_bytes(),
            RealmId(2),
            RoomId(3),
            Purpose::RateLimitRelief,
            manifest.hash(),
            manifest.contract(),
        )
        .unwrap();
    let wrong = WitnessSession::new(
        context(),
        verifying_key_from_seed([9; 32]),
        challenge,
        manifest,
        WorkAllowance { max_total: 1 },
        NOW,
    );
    assert!(matches!(
        wrong.err(),
        Some(SteelError::Witness(WitnessError::Context))
    ));
}
