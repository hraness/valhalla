//! Happy path, every refusal, replay, equivocation, capacity, pruning, state
//! loss, and byte-level tampering.

mod common;

use common::{Fixture, ENTROPY, LIFETIME, NOW};
use ed25519_dalek::SigningKey;
use vhalla_botcaptcha::admit::WitnessVerifier;
use vhalla_botcaptcha::challenge::{
    Algorithm, Challenge, ChallengeContext, Purpose, VerifiedChallenge, WitnessError,
    CHALLENGE_BYTES,
};
use vhalla_botcaptcha::response::{respond, ProveError, Response};
use vhalla_botcaptcha::window::{OneUseWindow, MAX_OPEN_CHALLENGES, MAX_OPEN_PER_SUBJECT};
use vhalla_botcaptcha::MAX_CHALLENGE_LIFETIME;
use vhalla_core::{RealmId, RoomId};
use vhalla_witness::manifest::ValidManifest;
use vhalla_witness::model::{Action, Program, Rule};
use vhalla_witness::platform::WorkAllowance;

fn verifier(fixture: &Fixture) -> WitnessVerifier {
    WitnessVerifier::new(NOW - 10, fixture.allowance, OneUseWindow::new())
}

fn prove(fixture: &Fixture, challenge: &Challenge) -> Response {
    let verified = VerifiedChallenge::verify(
        challenge.clone(),
        fixture.context(),
        NOW - 10,
        challenge.issued_at,
    )
    .unwrap();
    respond(
        &verified,
        &fixture.valid,
        fixture.candidate.clone(),
        fixture.allowance,
        &fixture.subject,
    )
    .unwrap()
}

#[test]
fn a_working_witness_is_admitted_once_and_rewarded_by_scope() {
    for id in ["fixture-opening-normal", "fixture-ark-plan-a"] {
        let fixture = Fixture::new(id);
        let challenge = fixture.issue(ENTROPY, NOW);
        assert_eq!(challenge.encode().len(), CHALLENGE_BYTES);
        assert_eq!(Challenge::decode(&challenge.encode()).unwrap(), challenge);
        let response = prove(&fixture, &challenge);
        assert_eq!(Response::decode(&response.encode()).unwrap(), response);
        let mut verifier = verifier(&fixture);
        let witness = verifier
            .verify_bytes(
                &challenge.encode(),
                &fixture.valid,
                &response.encode(),
                fixture.context(),
                NOW + 5,
            )
            .unwrap();
        assert_eq!(witness.scope_key(), challenge.scope_key());
        assert_eq!(witness.response_hash(), response.hash());
        assert_eq!(witness.purpose(), Purpose::RateLimitRelief);
        assert_eq!(witness.expires_at(), NOW + LIFETIME);
        assert!(witness.receipt().useful() >= fixture.contract().useful_floor);
        assert_eq!(verifier.window().len(), 1);
        // Exact resend: replay.
        assert_eq!(
            verifier
                .verify_response(
                    challenge.clone(),
                    &fixture.valid,
                    &response,
                    fixture.context(),
                    NOW + 6
                )
                .err(),
            Some(WitnessError::Replay),
            "{id}"
        );
        // Same challenge, different valid response (a re-signed body with a
        // nonce): equivocation, and the stored entry is kept.
        let mut other = response.clone();
        other.hashcash_nonce = Some(1);
        other.signature =
            ed25519_dalek::Signer::sign(&fixture.subject, &other.transcript()).to_bytes();
        assert_eq!(
            verifier
                .verify_response(
                    challenge.clone(),
                    &fixture.valid,
                    &other,
                    fixture.context(),
                    NOW + 7
                )
                .err(),
            Some(WitnessError::Equivocation),
            "{id}"
        );
        assert_eq!(
            verifier.window().consumed(&challenge.scope_key()),
            Some(response.hash())
        );
        // A fresh challenge for the same subject is a new scope with a new reward.
        let second = fixture.issue([43; 32], NOW + 8);
        let again = verifier
            .verify_response(
                second.clone(),
                &fixture.valid,
                &prove(&fixture, &second),
                fixture.context(),
                NOW + 9,
            )
            .unwrap();
        assert_ne!(again.reward(), witness.reward(), "{id}");
        // Pruning after expiry frees the scope; the challenge itself is then expired.
        verifier.prune(NOW + LIFETIME + 1);
        assert_eq!(
            verifier.window().len(),
            1,
            "the later challenge is still open"
        );
        verifier.prune(NOW + 8 + LIFETIME + 1);
        assert_eq!(verifier.window().len(), 0);
        assert_eq!(
            verifier
                .verify_response(
                    challenge,
                    &fixture.valid,
                    &response,
                    fixture.context(),
                    NOW + LIFETIME + 1
                )
                .err(),
            Some(WitnessError::Expired),
            "{id}"
        );
    }
}

#[test]
fn every_challenge_step_has_its_own_refusal() {
    let fixture = Fixture::new("fixture-opening-normal");
    let challenge = fixture.issue(ENTROPY, NOW);
    let response = prove(&fixture, &challenge);
    let check = |challenge: Challenge, expected: ChallengeContext, started_at: u64, now: u64| {
        WitnessVerifier::new(started_at, fixture.allowance, OneUseWindow::new())
            .verify_response(challenge, &fixture.valid, &response, expected, now)
            .err()
    };
    let ctx = fixture.context();
    assert_eq!(check(challenge.clone(), ctx, NOW - 10, NOW + 1), None);
    let mut c = challenge.clone();
    c.algorithm = Algorithm::Hashcash;
    assert_eq!(
        check(c, ctx, NOW - 10, NOW + 1),
        Some(WitnessError::Algorithm)
    );
    let mut c = challenge.clone();
    c.signature[3] ^= 1;
    assert_eq!(
        check(c, ctx, NOW - 10, NOW + 1),
        Some(WitnessError::IssuerSignature)
    );
    let mut c = challenge.clone();
    c.expires_at += 1;
    assert_eq!(
        check(c, ctx, NOW - 10, NOW + 1),
        Some(WitnessError::IssuerSignature)
    );
    for (label, wrong) in [
        (
            "issuer",
            ChallengeContext {
                issuer_key: [1; 32],
                ..ctx
            },
        ),
        (
            "subject",
            ChallengeContext {
                subject_key: [1; 32],
                ..ctx
            },
        ),
        (
            "realm",
            ChallengeContext {
                realm: RealmId(9),
                ..ctx
            },
        ),
        (
            "room",
            ChallengeContext {
                room: RoomId(9),
                ..ctx
            },
        ),
        (
            "purpose",
            ChallengeContext {
                purpose: Purpose::GameQualification,
                ..ctx
            },
        ),
    ] {
        let error = check(challenge.clone(), wrong, NOW - 10, NOW + 1);
        assert!(
            matches!(
                error,
                Some(WitnessError::Context | WitnessError::IssuerSignature)
            ),
            "{label}: {error:?}"
        );
    }
    assert_eq!(
        check(challenge.clone(), ctx, NOW - 10, NOW - 1),
        Some(WitnessError::NotYetValid)
    );
    assert_eq!(
        check(challenge.clone(), ctx, NOW - 10, NOW + LIFETIME + 1),
        Some(WitnessError::Expired)
    );
    assert_eq!(
        check(challenge.clone(), ctx, NOW + 1, NOW + 1),
        Some(WitnessError::BeforeVerifierStart)
    );
    assert_eq!(
        fixture
            .issuer
            .issue(
                [1; 32],
                NOW,
                MAX_CHALLENGE_LIFETIME + 1,
                fixture.subject_key(),
                RealmId(1),
                RoomId(2),
                Purpose::RateLimitRelief,
                fixture.valid.hash(),
                fixture.contract()
            )
            .err(),
        Some(vhalla_botcaptcha::challenge::IssueError::Lifetime)
    );
    let other = ValidManifest::validate(Fixture::new("fixture-ark-plan-a").manifest).unwrap();
    assert_eq!(
        WitnessVerifier::new(NOW - 10, fixture.allowance, OneUseWindow::new())
            .verify_response(challenge.clone(), &other, &response, ctx, NOW + 1)
            .err(),
        Some(WitnessError::Manifest)
    );
    let short = WorkAllowance {
        max_total: fixture.valid.fuel_total() - 1,
    };
    assert_eq!(
        WitnessVerifier::new(NOW - 10, short, OneUseWindow::new())
            .verify_response(challenge, &fixture.valid, &response, ctx, NOW + 1)
            .err(),
        Some(WitnessError::Allowance)
    );
}

#[test]
fn every_response_step_has_its_own_refusal() {
    let fixture = Fixture::new("fixture-opening-normal");
    let challenge = fixture.issue(ENTROPY, NOW);
    let response = prove(&fixture, &challenge);
    let check = |response: &Response| {
        verifier(&fixture)
            .verify_response(
                challenge.clone(),
                &fixture.valid,
                response,
                fixture.context(),
                NOW + 1,
            )
            .err()
    };
    let resign = |mut response: Response| {
        response.signature =
            ed25519_dalek::Signer::sign(&fixture.subject, &response.transcript()).to_bytes();
        response
    };
    let mut r = response.clone();
    r.signature[0] ^= 1;
    assert_eq!(check(&r), Some(WitnessError::SubjectSignature));
    let stranger = SigningKey::from_bytes(&[99; 32]);
    let mut r = response.clone();
    r.signature = ed25519_dalek::Signer::sign(&stranger, &r.transcript()).to_bytes();
    assert_eq!(check(&r), Some(WitnessError::SubjectSignature));
    let mut r = response.clone();
    r.challenge_id[0] ^= 1;
    assert_eq!(check(&resign(r)), Some(WitnessError::Binding));
    let mut r = response.clone();
    r.claimed.challenge_id[0] ^= 1;
    assert_eq!(check(&resign(r)), Some(WitnessError::Binding));
    let mut r = response.clone();
    r.measured_work.total += 1;
    assert_eq!(check(&resign(r)), Some(WitnessError::Claim));
    let mut r = response.clone();
    r.receipt_hash.0[0] ^= 1;
    assert_eq!(check(&resign(r)), Some(WitnessError::Claim));
    let mut r = response.clone();
    r.candidate.truncate(r.candidate.len() - 1);
    assert!(matches!(check(&resign(r)), Some(WitnessError::Codec(_))));
    let mut r = response.clone();
    r.candidate[3] ^= 0x40;
    assert!(matches!(
        check(&resign(r)),
        Some(WitnessError::Candidate | WitnessError::Codec(_) | WitnessError::Program)
    ));
    // A different valid program with an honest receipt hash but the claimed
    // program hash of the original: the program step catches it.
    let idle: Vec<(u16, Program)> = fixture
        .candidate
        .iter()
        .map(|(cell, _)| {
            (
                *cell,
                Program::new(vec![Rule::new(vec![], Action::Wait, None).unwrap()]).unwrap(),
            )
        })
        .collect();
    let mut r = response.clone();
    r.candidate = vhalla_witness::codec::encode_candidate(&idle);
    assert_eq!(check(&resign(r)), Some(WitnessError::Program));
    // A tampered receipt whose top-level fields are kept consistent: the
    // replay catches it.
    let mut r = response.clone();
    r.claimed.total -= 1;
    r.measured_work.total -= 1;
    r.receipt_hash = vhalla_witness::hash::ReceiptHash::of(&r.claimed.encode());
    assert_eq!(check(&resign(r)), Some(WitnessError::Receipt));
    // An honest idle program: it fails the floor.
    let verified = VerifiedChallenge::verify(
        challenge.clone(),
        fixture.context(),
        NOW - 10,
        challenge.issued_at,
    )
    .unwrap();
    let idle_response = respond(
        &verified,
        &fixture.valid,
        idle,
        fixture.allowance,
        &fixture.subject,
    )
    .unwrap();
    assert_eq!(check(&idle_response), Some(WitnessError::Floor));
    // The prover refuses the wrong subject key or manifest.
    assert_eq!(
        respond(
            &verified,
            &fixture.valid,
            fixture.candidate.clone(),
            fixture.allowance,
            &stranger
        )
        .err(),
        Some(ProveError::Subject)
    );
    let other = ValidManifest::validate(Fixture::new("fixture-ark-plan-a").manifest).unwrap();
    assert_eq!(
        respond(
            &verified,
            &other,
            fixture.candidate.clone(),
            fixture.allowance,
            &fixture.subject
        )
        .err(),
        Some(ProveError::Manifest)
    );
}

#[test]
fn any_single_byte_change_to_the_wire_is_refused() {
    let fixture = Fixture::new("fixture-opening-normal");
    let challenge = fixture.issue(ENTROPY, NOW);
    let response = prove(&fixture, &challenge);
    let challenge_bytes = challenge.encode();
    let response_bytes = response.encode();
    for index in 0..challenge_bytes.len() {
        let mut bytes = challenge_bytes.clone();
        bytes[index] ^= 1;
        let result = verifier(&fixture).verify_bytes(
            &bytes,
            &fixture.valid,
            &response_bytes,
            fixture.context(),
            NOW + 1,
        );
        assert!(result.is_err(), "challenge byte {index}");
    }
    for index in 0..response_bytes.len() {
        let mut bytes = response_bytes.clone();
        bytes[index] ^= 1;
        let result = verifier(&fixture).verify_bytes(
            &challenge_bytes,
            &fixture.valid,
            &bytes,
            fixture.context(),
            NOW + 1,
        );
        assert!(result.is_err(), "response byte {index}");
    }
    let ok = verifier(&fixture).verify_bytes(
        &challenge_bytes,
        &fixture.valid,
        &response_bytes,
        fixture.context(),
        NOW + 1,
    );
    assert!(ok.is_ok());
}

#[test]
fn the_window_fills_to_capacity_and_a_restart_refuses_older_challenges() {
    let fixture = Fixture::new("fixture-opening-normal");
    let mut verifier = verifier(&fixture);
    // MAX_OPEN_CHALLENGES / MAX_OPEN_PER_SUBJECT distinct subjects fill the window.
    let subjects = MAX_OPEN_CHALLENGES / MAX_OPEN_PER_SUBJECT;
    for subject in 0..subjects {
        let mut seed = [0_u8; 32];
        seed[..8].copy_from_slice(&(subject as u64 + 100).to_be_bytes());
        let key = SigningKey::from_bytes(&seed);
        let subject_key = key.verifying_key().to_bytes();
        let context = ChallengeContext {
            subject_key,
            ..fixture.context()
        };
        for index in 0..MAX_OPEN_PER_SUBJECT {
            let mut entropy = [0_u8; 32];
            entropy[..8]
                .copy_from_slice(&((subject * MAX_OPEN_PER_SUBJECT + index) as u64).to_be_bytes());
            let challenge = fixture
                .issuer
                .issue(
                    entropy,
                    NOW,
                    LIFETIME,
                    subject_key,
                    common::REALM,
                    common::ROOM,
                    Purpose::RateLimitRelief,
                    fixture.valid.hash(),
                    fixture.contract(),
                )
                .unwrap();
            let verified =
                VerifiedChallenge::verify(challenge.clone(), context, NOW - 10, NOW).unwrap();
            let response = respond(
                &verified,
                &fixture.valid,
                fixture.candidate.clone(),
                fixture.allowance,
                &key,
            )
            .unwrap();
            verifier
                .verify_response(challenge, &fixture.valid, &response, context, NOW + 1)
                .unwrap();
        }
    }
    assert_eq!(verifier.window().len(), MAX_OPEN_CHALLENGES);
    let challenge = fixture.issue([255; 32], NOW);
    let response = prove(&fixture, &challenge);
    assert_eq!(
        verifier
            .verify_response(
                challenge.clone(),
                &fixture.valid,
                &response,
                fixture.context(),
                NOW + 1
            )
            .err(),
        Some(WitnessError::Capacity)
    );
    verifier.prune(NOW + LIFETIME + 1);
    assert!(verifier.window().is_empty());
    // After state loss the verifier restarts with a fresh started_at and
    // refuses every challenge issued before it.
    let mut restarted = WitnessVerifier::new(NOW + 2, fixture.allowance, OneUseWindow::new());
    assert_eq!(
        restarted
            .verify_response(
                challenge,
                &fixture.valid,
                &response,
                fixture.context(),
                NOW + 3
            )
            .err(),
        Some(WitnessError::BeforeVerifierStart)
    );
    let fresh = fixture.issue([254; 32], NOW + 2);
    assert!(restarted
        .verify_response(
            fresh.clone(),
            &fixture.valid,
            &prove(&fixture, &fresh),
            fixture.context(),
            NOW + 3
        )
        .is_ok());
}

#[test]
fn a_replayed_response_is_refused_before_any_replay_work() {
    let fixture = Fixture::new("fixture-opening-normal");
    let challenge = fixture.issue(ENTROPY, NOW);
    let response = prove(&fixture, &challenge);
    let mut verifier = verifier(&fixture);
    verifier
        .verify_response(
            challenge.clone(),
            &fixture.valid,
            &response,
            fixture.context(),
            NOW + 1,
        )
        .unwrap();
    // With the allowance made too small, a fresh response would fail at the
    // allowance step; the consumed one is refused earlier, at the window peek.
    verifier.set_allowance(WorkAllowance { max_total: 1 });
    assert_eq!(
        verifier
            .verify_response(
                challenge.clone(),
                &fixture.valid,
                &response,
                fixture.context(),
                NOW + 2
            )
            .err(),
        Some(WitnessError::Replay)
    );
    let mut other = response.clone();
    other.hashcash_nonce = Some(7);
    other.signature = ed25519_dalek::Signer::sign(&fixture.subject, &other.transcript()).to_bytes();
    assert_eq!(
        verifier
            .verify_response(
                challenge,
                &fixture.valid,
                &other,
                fixture.context(),
                NOW + 3
            )
            .err(),
        Some(WitnessError::Equivocation)
    );
}

#[test]
fn a_response_binds_the_exact_challenge_not_just_its_id() {
    let fixture = Fixture::new("fixture-opening-normal");
    let first = fixture.issue(ENTROPY, NOW);
    let response = prove(&fixture, &first);
    // The issuer re-issues with the same entropy one second later: same id,
    // same subject, same manifest, different expiry and signature.
    let reissued = fixture.issue(ENTROPY, NOW + 1);
    assert_eq!(reissued.challenge_id, first.challenge_id);
    assert_ne!(reissued.hash(), first.hash());
    assert_eq!(
        verifier(&fixture)
            .verify_response(
                reissued,
                &fixture.valid,
                &response,
                fixture.context(),
                NOW + 2
            )
            .err(),
        Some(WitnessError::Binding)
    );
}

#[test]
fn the_verifier_clock_never_runs_backwards() {
    let fixture = Fixture::new("fixture-opening-normal");
    let challenge = fixture.issue(ENTROPY, NOW);
    let response = prove(&fixture, &challenge);
    let mut verifier = verifier(&fixture);
    verifier
        .verify_response(
            challenge.clone(),
            &fixture.valid,
            &response,
            fixture.context(),
            NOW + 1,
        )
        .unwrap();
    verifier.prune(NOW + LIFETIME + 1);
    assert!(verifier.window().is_empty());
    // A smaller injected `now` after the prune must not re-admit the response.
    assert_eq!(
        verifier
            .verify_response(
                challenge,
                &fixture.valid,
                &response,
                fixture.context(),
                NOW + 2
            )
            .err(),
        Some(WitnessError::Expired)
    );
}

#[test]
fn one_subject_cannot_fill_the_window() {
    let fixture = Fixture::new("fixture-opening-normal");
    let mut verifier = verifier(&fixture);
    for index in 0..MAX_OPEN_PER_SUBJECT {
        let mut entropy = [1_u8; 32];
        entropy[..8].copy_from_slice(&(index as u64).to_be_bytes());
        let challenge = fixture.issue(entropy, NOW);
        let response = prove(&fixture, &challenge);
        verifier
            .verify_response(
                challenge,
                &fixture.valid,
                &response,
                fixture.context(),
                NOW + 1,
            )
            .unwrap();
    }
    assert_eq!(
        verifier.window().held_by(&fixture.subject_key()),
        MAX_OPEN_PER_SUBJECT
    );
    let challenge = fixture.issue([200; 32], NOW);
    let response = prove(&fixture, &challenge);
    assert_eq!(
        verifier
            .verify_response(
                challenge.clone(),
                &fixture.valid,
                &response,
                fixture.context(),
                NOW + 1
            )
            .err(),
        Some(WitnessError::SubjectCapacity)
    );
    assert!(verifier.window().len() < MAX_OPEN_CHALLENGES);
    verifier.prune(NOW + LIFETIME + 1);
    assert_eq!(verifier.window().held_by(&fixture.subject_key()), 0);
}
