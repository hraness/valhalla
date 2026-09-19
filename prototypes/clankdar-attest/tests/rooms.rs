//! Rooms admission dogfood tests: the room-side issue → submit → decide
//! round-trip over fabricated generator instances — no clankdar checkout,
//! exactly like the gate tests' fabricated oracle.

use std::collections::BTreeMap;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use valhalla_clankdar_attest_prototype::*;

const NOW: &str = "2026-09-18T00:00:00Z";
const LATER: &str = "2026-09-18T00:01:00Z";

fn at(iso: &str) -> OffsetDateTime {
    OffsetDateTime::parse(iso, &Rfc3339).unwrap()
}

/// The room's issuer key — a raw seed like the other test keys, not a
/// cryptographic-looking literal.
fn signing() -> SigningKey {
    SigningKey::from_bytes(&[7u8; 32])
}

/// A second issuer for "not this room" cases.
fn foreign_signing() -> SigningKey {
    SigningKey::from_bytes(&[9u8; 32])
}

fn public_key(key: &SigningKey) -> String {
    URL_SAFE_NO_PAD.encode(key.verifying_key().to_bytes())
}

/// A fabricated generator oracle: instances derived from the requested
/// cell and seed at runtime, so no fixture answer is ever a literal. The
/// frontier cells under test all score in the integer format, so the
/// derived answers are canonical by construction.
fn generate(
    suite_version: &str,
    family: &str,
    tier: u32,
    seed: u64,
) -> Result<GeneratedInstance, String> {
    if suite_version != FRONTIER_SUITE_VERSION {
        return Err(format!("no suite pool {suite_version}"));
    }
    Ok(GeneratedInstance {
        suite_version: suite_version.to_string(),
        family: family.to_string(),
        tier,
        seed,
        prompt: format!("{family} t{tier} puzzle drawn for seed {seed}"),
        answer: format!("{}", seed % 100_000 + u64::from(tier)),
    })
}

fn policy() -> GatePolicy {
    GatePolicy::parse(&json!({
        "suite": "frontier",
        "cells": ["cryptarithm:t6", "registervm:t5"],
        "challenges": 3,
        "minPass": 2,
        "ttlSeconds": 300,
    }))
    .unwrap()
}

/// Mint a session under the room key with a deterministic cell pick
/// (cycling the policy cells) and a deterministic seed base — the
/// `pick`/`seedBase` hooks exist for exactly this.
fn issue(policy: &GatePolicy) -> RoomSession {
    issue_as(policy, &signing())
}

fn issue_as(policy: &GatePolicy, key: &SigningKey) -> RoomSession {
    let mut n = 0usize;
    issue_room_session(
        policy,
        key,
        &RoomSessionOptions {
            subject: Some("agent-7"),
            context: Some("room:valhalla-room-1"),
            now: Some(at(NOW)),
            seed_base: Some(700_000),
        },
        move |bound| {
            let index = n % bound;
            n += 1;
            index
        },
        generate,
    )
    .unwrap()
}

/// The room's pinned floor: the published policy plus the issuer's public
/// key — the two things a joining agent could look up.
fn floor<'a>(policy: &'a GatePolicy, issuer: &SigningKey) -> RoomFloor<'a> {
    RoomFloor {
        policy,
        verifier_key: public_key(issuer),
    }
}

/// Every challenge answered with its committed expected answer.
fn all_correct(session: &RoomSession) -> BTreeMap<String, String> {
    session
        .tickets
        .iter()
        .map(|t| (t.challenge.challenge_id.clone(), t.expected.clone()))
        .collect()
}

fn submit(session: &RoomSession, responses: &BTreeMap<String, String>) -> RoomSubmission {
    submit_room_session(
        session,
        responses,
        &signing(),
        None,
        Some(at(LATER)),
        generate,
    )
    .unwrap()
}

// --- the round-trip --------------------------------------------------------

#[test]
fn a_room_session_round_trips_to_admit() {
    let policy = policy();
    let session = issue(&policy);
    // The minted session is bound: gate kind, one session id, one shared
    // deadline, policy cells only, subject/context carried through.
    assert_eq!(session.protocol, GATE_PROTOCOL);
    assert_eq!(session.kind, "session");
    assert!(session.session_id.starts_with("gs_"));
    assert_eq!(session.tickets.len() as u64, policy.challenges);
    for ticket in &session.tickets {
        let challenge = &ticket.challenge;
        assert_eq!(
            challenge.session_id.as_deref(),
            Some(session.session_id.as_str())
        );
        assert_eq!(challenge.expires_at, session.expires_at);
        assert_eq!(challenge.suite_version, FRONTIER_SUITE_VERSION);
        assert_eq!(challenge.subject.as_deref(), Some("agent-7"));
        assert_eq!(challenge.context.as_deref(), Some("room:valhalla-room-1"));
        let cell = format!("{}:t{}", challenge.family, challenge.tier);
        assert!(policy.cells.contains(&cell), "{cell} outside the floor");
    }
    let submission = submit(&session, &all_correct(&session));
    assert_eq!(submission.receipts.len() as u64, policy.challenges);
    // The admission independently replays, then the room decides under
    // its own floor and key.
    let check = check_admission(&submission.admission, generate);
    assert!(check.ok, "{:?}", check.reason);
    assert_eq!(check.verdict, Some(true));
    let decision =
        decide_room_admission(&submission.admission, &floor(&policy, &signing()), generate);
    assert!(decision.admit, "{}", decision.reason);
}

#[test]
fn a_session_below_the_floor_denies() {
    let policy = policy();
    let session = issue(&policy);
    // One correct answer out of three challenges: minPass 2 is not met,
    // and the signed admission says so honestly.
    let mut responses = BTreeMap::new();
    let ticket = &session.tickets[0];
    responses.insert(
        ticket.challenge.challenge_id.clone(),
        ticket.expected.clone(),
    );
    let submission = submit(&session, &responses);
    let check = check_admission(&submission.admission, generate);
    assert!(check.ok, "{:?}", check.reason);
    assert_eq!(check.verdict, Some(false));
    let decision =
        decide_room_admission(&submission.admission, &floor(&policy, &signing()), generate);
    assert!(!decision.admit);
    assert!(decision.reason.contains("floor"), "{}", decision.reason);
}

// --- the decision reads the signed verdict, not a claim ----------------------

#[test]
fn the_decision_consumes_the_signed_verdict_not_a_claim() {
    let policy = policy();
    let session = issue(&policy);
    // An honestly failed session: the signed verdict records the miss.
    let mut responses = BTreeMap::new();
    let ticket = &session.tickets[0];
    responses.insert(
        ticket.challenge.challenge_id.clone(),
        ticket.expected.clone(),
    );
    let failed = submit(&session, &responses);
    let floor = floor(&policy, &signing());
    assert!(!decide_room_admission(&failed.admission, &floor, generate).admit);
    // Relabel the signed body as a pass — re-signed under the room key, so
    // only the replayed verdict arithmetic can catch it. A decision that
    // trusted the recorded `pass` flag would admit; this one cannot.
    let mut body: Value = serde_json::from_str(&failed.admission.payload).unwrap();
    body["verdict"]["pass"] = json!(true);
    let payload = canonical_json(&body);
    let forged = Admission {
        protocol: GATE_PROTOCOL.to_string(),
        payload: payload.clone(),
        signature: URL_SAFE_NO_PAD.encode(signing().sign(payload.as_bytes()).to_bytes()),
    };
    let decision = decide_room_admission(&forged, &floor, generate);
    assert!(!decision.admit, "a claimed pass must not admit");
    assert!(
        decision.reason.contains("does not verify"),
        "{}",
        decision.reason
    );
    // And the inverse: claiming a miss on a passing session also fails —
    // the verdict is recomputed, never read off the body.
    let passing = submit(&session, &all_correct(&session));
    let mut body: Value = serde_json::from_str(&passing.admission.payload).unwrap();
    body["verdict"]["pass"] = json!(false);
    let payload = canonical_json(&body);
    let forged = Admission {
        protocol: GATE_PROTOCOL.to_string(),
        payload: payload.clone(),
        signature: URL_SAFE_NO_PAD.encode(signing().sign(payload.as_bytes()).to_bytes()),
    };
    assert!(!decide_room_admission(&forged, &floor, generate).admit);
    // The untouched passing admission still admits — the decision is the
    // signed artifact's replayed verdict plus the room's pins, end to end.
    assert!(decide_room_admission(&passing.admission, &floor, generate).admit);
}

#[test]
fn an_admission_from_another_room_is_denied() {
    let policy = policy();
    let session = issue(&policy);
    let submission = submit(&session, &all_correct(&session));
    // Same admission, pinned to a different floor: not this room's pass.
    let other_policy = GatePolicy::parse(&json!({
        "suite": "frontier",
        "cells": ["cryptarithm:t6"],
        "challenges": 3,
        "minPass": 2,
        "ttlSeconds": 300,
    }))
    .unwrap();
    let decision = decide_room_admission(
        &submission.admission,
        &floor(&other_policy, &signing()),
        generate,
    );
    assert!(!decision.admit, "{}", decision.reason);
    assert!(decision.reason.contains("floor"), "{}", decision.reason);
    // Same admission, pinned to a different verifier key: not this room's
    // issuer, even though the admission itself verifies.
    let decision = decide_room_admission(
        &submission.admission,
        &floor(&policy, &foreign_signing()),
        generate,
    );
    assert!(!decision.admit);
    assert!(
        decision.reason.contains("verifier key"),
        "{}",
        decision.reason
    );
    // An admission minted wholesale by a foreign issuer fails earlier —
    // its signature verifies under the foreign key, but the room pin and
    // the verdict path still drive a deny.
    let foreign_session = issue_as(&policy, &foreign_signing());
    let foreign_submission = submit_room_session(
        &foreign_session,
        &all_correct(&foreign_session),
        &foreign_signing(),
        None,
        Some(at(LATER)),
        generate,
    )
    .unwrap();
    let check = check_admission(&foreign_submission.admission, generate);
    assert!(
        check.ok,
        "the foreign admission does verify on its own terms"
    );
    let decision = decide_room_admission(
        &foreign_submission.admission,
        &floor(&policy, &signing()),
        generate,
    );
    assert!(!decision.admit);
}

// --- submit guards ------------------------------------------------------------

#[test]
fn a_room_denies_held_out_scores_it_cannot_replay() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/ts_admission_holdout.json")).unwrap();
    let admission: Admission = serde_json::from_value(fixture["admission"].clone()).unwrap();
    let body: Value = serde_json::from_str(&admission.payload).unwrap();
    let policy = GatePolicy::parse(&body["policy"]).unwrap();
    let verifier_key = body["challenges"][0]["verifier"]["publicKey"]
        .as_str()
        .unwrap()
        .to_string();
    let decision = decide_room_admission(
        &admission,
        &RoomFloor {
            policy: &policy,
            verifier_key,
        },
        generate,
    );
    assert!(!decision.admit);
    assert!(
        decision.reason.contains("did not replay"),
        "{}",
        decision.reason
    );
}

#[test]
fn missing_and_noncanonical_answers_are_failed_challenges() {
    let policy = policy();
    let session = issue(&policy);
    let mut responses = BTreeMap::new();
    let first = &session.tickets[0];
    responses.insert(first.challenge.challenge_id.clone(), first.expected.clone());
    // A chatty answer is not format-canonical for an integer cell: it is a
    // failed challenge with no receipt, never a scored attempt.
    responses.insert(
        session.tickets[1].challenge.challenge_id.clone(),
        format!("the answer is {}", session.tickets[1].expected),
    );
    // tickets[2] is simply unanswered.
    let submission = submit(&session, &responses);
    assert_eq!(submission.receipts.len(), 1);
    let check = check_admission(&submission.admission, generate);
    assert!(check.ok, "{:?}", check.reason);
    assert_eq!(check.passed, Some(1));
    assert_eq!(check.verdict, Some(false));
    let decision =
        decide_room_admission(&submission.admission, &floor(&policy, &signing()), generate);
    assert!(!decision.admit);
}

#[test]
fn submit_rejects_unknown_responses_and_expired_sessions() {
    let policy = policy();
    let session = issue(&policy);
    let mut responses = BTreeMap::new();
    responses.insert("att_unknown000".to_string(), "1".to_string());
    let error = submit_room_session(
        &session,
        &responses,
        &signing(),
        None,
        Some(at(LATER)),
        generate,
    )
    .unwrap_err();
    assert!(matches!(error, AttestError::InvalidInput(_)), "{error}");
    // A submit after the shared deadline refuses before scoring anything.
    let past = at("2026-09-18T00:06:00Z"); // expiresAt = NOW + 300s
    assert_eq!(
        submit_room_session(
            &session,
            &BTreeMap::new(),
            &signing(),
            None,
            Some(past),
            generate
        )
        .unwrap_err(),
        AttestError::Expired
    );
}

#[test]
fn submit_replays_the_completed_admission_before_returning_it() {
    let policy = policy();
    let mut session = issue(&policy);
    session.context = Some("room:tampered-private-state".to_string());
    let error = submit_room_session(
        &session,
        &all_correct(&session),
        &signing(),
        None,
        Some(at(LATER)),
        generate,
    )
    .unwrap_err();
    assert!(matches!(&error, AttestError::Mismatch(_)), "{error}");
    assert!(error
        .to_string()
        .contains("minted admission does not verify"));
}

#[test]
fn issue_validates_the_floor_and_the_seed_space() {
    // A struct-invalid policy never reaches minting.
    let mut bad = policy();
    bad.min_pass = bad.challenges + 1;
    assert!(issue_room_session(
        &bad,
        &signing(),
        &RoomSessionOptions::default(),
        |_| 0,
        generate,
    )
    .is_err());
    // A seed base that would push a drawn seed past uint32 is refused.
    let policy = policy();
    for seed_base in [u64::from(u32::MAX), u64::MAX] {
        assert!(issue_room_session(
            &policy,
            &signing(),
            &RoomSessionOptions {
                seed_base: Some(seed_base),
                ..RoomSessionOptions::default()
            },
            |_| 0,
            generate,
        )
        .is_err());
    }
    // And a pick that falls outside the cells is refused, not wrapped.
    assert!(issue_room_session(
        &policy,
        &signing(),
        &RoomSessionOptions::default(),
        |bound| bound + 1,
        generate,
    )
    .is_err());
}

// --- session shape and subject binding ----------------------------------------

#[test]
fn challenges_draw_from_the_policy_cells_with_replacement() {
    let policy = policy();
    let session = issue(&policy);
    // The deterministic pick cycles 0, 1, 0 — the same cell drawn twice
    // proves replacement, and every draw lands inside the floor.
    let families: Vec<&str> = session
        .tickets
        .iter()
        .map(|t| t.challenge.family.as_str())
        .collect();
    assert_eq!(families, ["cryptarithm", "registervm", "cryptarithm"]);
}

#[test]
fn a_subject_proofed_session_binds_one_respondent_key() {
    let policy = policy();
    let session = issue(&policy);
    let respondent = generate_verifier();
    // Session scope: one proof minted against any listed challenge covers
    // the whole session — the respondent's half of the handshake.
    let proof = subject_proof_for(&session.tickets[0].challenge, &respondent).unwrap();
    let submission = submit_room_session(
        &session,
        &all_correct(&session),
        &signing(),
        Some(&proof),
        Some(at(LATER)),
        generate,
    )
    .unwrap();
    for receipt in &submission.receipts {
        let body: ReceiptBody = serde_json::from_str(&receipt.payload).unwrap();
        let embedded: SubjectProof =
            serde_json::from_value(body.subject_proof.expect("proof embedded")).unwrap();
        assert_eq!(embedded.public_key, proof.public_key);
    }
    let check = check_admission(&submission.admission, generate);
    assert!(check.ok, "{:?}", check.reason);
    assert_eq!(check.passed, Some(3));
    let decision =
        decide_room_admission(&submission.admission, &floor(&policy, &signing()), generate);
    assert!(decision.admit, "{}", decision.reason);
}

#[test]
fn the_session_serializes_the_gate_session_shape() {
    let policy = policy();
    let session = issue(&policy);
    let value = serde_json::to_value(&session).unwrap();
    // Member names mirror bench/gate.ts's GateSession: a serialized
    // session round-trips the TypeScript wire shape.
    assert_eq!(value["protocol"], json!(GATE_PROTOCOL));
    assert_eq!(value["kind"], json!("session"));
    assert!(value["sessionId"].as_str().unwrap().starts_with("gs_"));
    assert_eq!(value["subject"], json!("agent-7"));
    assert_eq!(value["context"], json!("room:valhalla-room-1"));
    assert!(value.get("issuedAt").is_some());
    assert_eq!(value["expiresAt"], json!(session.expires_at));
    assert_eq!(
        value["tickets"].as_array().unwrap().len() as u64,
        policy.challenges
    );
    let round_trip: RoomSession = serde_json::from_value(value).unwrap();
    assert_eq!(round_trip.session_id, session.session_id);
    assert_eq!(round_trip.tickets.len(), session.tickets.len());
}
