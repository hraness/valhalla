//! Hashcash mode: solve and admit once, replay and equivocation, insufficient
//! work, algorithm mismatch both ways, and byte-level tampering.

mod common;

use common::{Fixture, ENTROPY, LIFETIME, NOW};
use ed25519_dalek::SigningKey;
use vhalla_botcaptcha::admit::WitnessVerifier;
use vhalla_botcaptcha::challenge::{
    Algorithm, Challenge, Difficulty, Purpose, Requirement, VerifiedChallenge, WitnessError,
    MAX_DIFFICULTY,
};
use vhalla_botcaptcha::hashcash::{
    leading_zero_bits, respond_hashcash, solve, work_digest, HashcashResponse, RespondError,
    SolveError, HASHCASH_RESPONSE_BYTES,
};
use vhalla_botcaptcha::response::{respond, ProveError};
use vhalla_botcaptcha::window::OneUseWindow;
use vhalla_core::{RealmId, RoomId};

const DIFFICULTY: u8 = 10;

fn issue(fixture: &Fixture, entropy: [u8; 32], now: u64, bits: u8) -> Challenge {
    fixture
        .issuer
        .issue_hashcash(
            entropy,
            now,
            LIFETIME,
            fixture.subject_key(),
            common::REALM,
            common::ROOM,
            Purpose::RateLimitRelief,
            Difficulty::new(bits).unwrap(),
        )
        .unwrap()
}

fn verified(fixture: &Fixture, challenge: &Challenge) -> VerifiedChallenge {
    VerifiedChallenge::verify(
        challenge.clone(),
        fixture.context(),
        NOW - 10,
        challenge.issued_at,
    )
    .unwrap()
}

fn verifier(fixture: &Fixture) -> WitnessVerifier {
    WitnessVerifier::new(NOW - 10, fixture.allowance, OneUseWindow::new())
}

#[test]
fn a_solved_challenge_is_admitted_once() {
    let fixture = Fixture::new("fixture-opening-normal");
    let challenge = issue(&fixture, ENTROPY, NOW, DIFFICULTY);
    assert_eq!(challenge.algorithm, Algorithm::Hashcash);
    assert_eq!(
        challenge.requirement,
        Requirement::Hashcash(Difficulty::new(DIFFICULTY).unwrap())
    );
    assert_eq!(Challenge::decode(&challenge.encode()).unwrap(), challenge);
    let verified = verified(&fixture, &challenge);
    let nonce = solve(&verified, 1 << 20).unwrap();
    let work = work_digest(challenge.hash(), fixture.subject_key(), nonce);
    assert!(leading_zero_bits(&work) >= u32::from(DIFFICULTY));
    let response = respond_hashcash(&verified, nonce, &fixture.subject).unwrap();
    assert_eq!(response.encode().len(), HASHCASH_RESPONSE_BYTES);
    assert_eq!(
        HashcashResponse::decode(&response.encode()).unwrap(),
        response
    );
    let mut verifier = verifier(&fixture);
    let admitted = verifier
        .verify_hashcash(challenge.clone(), &response, fixture.context(), NOW + 1)
        .unwrap();
    assert_eq!(admitted.work(), work);
    assert_eq!(admitted.difficulty().bits(), DIFFICULTY);
    assert_eq!(admitted.scope_key(), challenge.scope_key());
    assert_eq!(verifier.window().len(), 1);
    assert_eq!(
        verifier
            .verify_hashcash(challenge.clone(), &response, fixture.context(), NOW + 2)
            .err(),
        Some(WitnessError::Replay)
    );
    // A second valid nonce for the same challenge is equivocation, not a
    // second reward.
    let other_nonce = (nonce + 1..)
        .find(|n| {
            leading_zero_bits(&work_digest(challenge.hash(), fixture.subject_key(), *n))
                >= u32::from(DIFFICULTY)
        })
        .unwrap();
    let other = respond_hashcash(&verified, other_nonce, &fixture.subject).unwrap();
    assert_eq!(
        verifier
            .verify_hashcash(challenge, &other, fixture.context(), NOW + 3)
            .err(),
        Some(WitnessError::Equivocation)
    );
}

#[test]
fn insufficient_work_and_wrong_bindings_are_refused() {
    let fixture = Fixture::new("fixture-opening-normal");
    let challenge = issue(&fixture, ENTROPY, NOW, DIFFICULTY);
    let verified = verified(&fixture, &challenge);
    let nonce = solve(&verified, 1 << 20).unwrap();
    let bad_nonce = (0..)
        .find(|n| {
            leading_zero_bits(&work_digest(challenge.hash(), fixture.subject_key(), *n))
                < u32::from(DIFFICULTY)
        })
        .unwrap();
    let weak = respond_hashcash(&verified, bad_nonce, &fixture.subject).unwrap();
    assert_eq!(
        verifier(&fixture)
            .verify_hashcash(challenge.clone(), &weak, fixture.context(), NOW + 1)
            .err(),
        Some(WitnessError::InsufficientWork)
    );
    assert!(verifier(&fixture).window().is_empty());
    let good = respond_hashcash(&verified, nonce, &fixture.subject).unwrap();
    // Re-issued challenge with the same id: the response binds the exact one.
    let reissued = issue(&fixture, ENTROPY, NOW + 1, DIFFICULTY);
    assert_eq!(
        verifier(&fixture)
            .verify_hashcash(reissued, &good, fixture.context(), NOW + 2)
            .err(),
        Some(WitnessError::Binding)
    );
    // A stranger cannot sign for the subject.
    let stranger = SigningKey::from_bytes(&[99; 32]);
    assert_eq!(
        respond_hashcash(&verified, nonce, &stranger).err(),
        Some(RespondError::Subject)
    );
    let mut forged = good;
    forged.signature = ed25519_dalek::Signer::sign(&stranger, &forged.transcript()).to_bytes();
    assert_eq!(
        verifier(&fixture)
            .verify_hashcash(challenge.clone(), &forged, fixture.context(), NOW + 1)
            .err(),
        Some(WitnessError::SubjectSignature)
    );
    // Every single-byte change to either wire form is refused.
    let challenge_bytes = challenge.encode();
    let response_bytes = good.encode();
    for index in 0..challenge_bytes.len() {
        let mut bytes = challenge_bytes.clone();
        bytes[index] ^= 1;
        let result = Challenge::decode(&bytes)
            .map_err(WitnessError::Codec)
            .and_then(|c| verifier(&fixture).verify_hashcash(c, &good, fixture.context(), NOW + 1));
        assert!(result.is_err(), "challenge byte {index}");
    }
    for index in 0..response_bytes.len() {
        let mut bytes = response_bytes.clone();
        bytes[index] ^= 1;
        let result = HashcashResponse::decode(&bytes)
            .map_err(WitnessError::Codec)
            .and_then(|r| {
                verifier(&fixture).verify_hashcash(
                    challenge.clone(),
                    &r,
                    fixture.context(),
                    NOW + 1,
                )
            });
        assert!(result.is_err(), "response byte {index}");
    }
}

#[test]
fn the_two_modes_do_not_cross() {
    let fixture = Fixture::new("fixture-opening-normal");
    let hashcash = issue(&fixture, ENTROPY, NOW, DIFFICULTY);
    let witness = fixture.issue([2; 32], NOW);
    let hashcash_verified = verified(&fixture, &hashcash);
    let witness_verified = verified(&fixture, &witness);
    assert_eq!(
        solve(&witness_verified, 10).err(),
        Some(SolveError::Algorithm)
    );
    assert_eq!(
        respond_hashcash(&witness_verified, 0, &fixture.subject).err(),
        Some(RespondError::Algorithm)
    );
    assert_eq!(
        respond(
            &hashcash_verified,
            &fixture.valid,
            fixture.candidate.clone(),
            fixture.allowance,
            &fixture.subject
        )
        .err(),
        Some(ProveError::Algorithm)
    );
    let nonce = solve(&hashcash_verified, 1 << 20).unwrap();
    let response = respond_hashcash(&hashcash_verified, nonce, &fixture.subject).unwrap();
    // A Hashcash response against a witness challenge with the same id and
    // subject: the algorithm step refuses it before any binding check.
    let mut lookalike = witness.clone();
    lookalike.challenge_id = hashcash.challenge_id;
    assert!(matches!(
        verifier(&fixture)
            .verify_hashcash(lookalike, &response, fixture.context(), NOW + 1)
            .err(),
        Some(WitnessError::IssuerSignature | WitnessError::Algorithm)
    ));
    assert_eq!(
        verifier(&fixture)
            .verify_hashcash(witness, &response, fixture.context(), NOW + 1)
            .err(),
        Some(WitnessError::Algorithm)
    );
    let witness_response = respond(
        &witness_verified,
        &fixture.valid,
        fixture.candidate.clone(),
        fixture.allowance,
        &fixture.subject,
    )
    .unwrap();
    assert_eq!(
        verifier(&fixture)
            .verify_response(
                hashcash,
                &fixture.valid,
                &witness_response,
                fixture.context(),
                NOW + 1
            )
            .err(),
        Some(WitnessError::Algorithm)
    );
}

#[test]
fn difficulty_is_bounded_and_canonical() {
    assert!(Difficulty::new(0).is_none());
    assert!(Difficulty::new(MAX_DIFFICULTY + 1).is_none());
    assert_eq!(
        Difficulty::new(MAX_DIFFICULTY).unwrap().bits(),
        MAX_DIFFICULTY
    );
    let fixture = Fixture::new("fixture-opening-normal");
    let challenge = issue(&fixture, ENTROPY, NOW, 1);
    let mut bytes = challenge.encode();
    // The unused ceiling and flag bytes must be zero in Hashcash mode.
    let flag = bytes.len() - 64 - 1;
    bytes[flag] = 1;
    assert!(Challenge::decode(&bytes).is_err());
    let mut bytes = challenge.encode();
    let bits = bytes.len() - 64 - 17 + 7;
    bytes[bits] = MAX_DIFFICULTY + 1;
    assert!(Challenge::decode(&bytes).is_err());
    let _ = (RealmId(1), RoomId(2));
}
