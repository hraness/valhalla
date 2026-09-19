//! Admission-session (clankdar-gate-v1) policy and checking tests.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use valhalla_clankdar_attest_prototype::*;

const NOW: &str = "2026-09-18T00:00:00Z";
const LATER: &str = "2026-09-18T00:01:00Z";
const SESSION: &str = "gs_aaaaaaaaaaaa";

fn at(iso: &str) -> OffsetDateTime {
    OffsetDateTime::parse(iso, &Rfc3339).unwrap()
}

fn signing() -> SigningKey {
    SigningKey::from_bytes(&[7u8; 32])
}

fn instance(family: &str, tier: u32, seed: u64, prompt: &str, answer: &str) -> GeneratedInstance {
    GeneratedInstance {
        suite_version: FRONTIER_SUITE_VERSION.to_string(),
        family: family.to_string(),
        tier,
        seed,
        prompt: prompt.to_string(),
        answer: answer.to_string(),
    }
}

/// A fabricated session: challenges minted entirely in Rust through
/// `issue_challenge`, so no generator oracle is needed to construct them.
struct Session {
    policy: GatePolicy,
    challenges: Vec<Challenge>,
    tickets: Vec<Ticket>,
    instances: Vec<GeneratedInstance>,
}

fn issue_session(cells: &[(&str, u32)], min_pass: u64) -> Session {
    issue_session_bound(cells, min_pass, None, None, SESSION)
}

fn issue_session_bound(
    cells: &[(&str, u32)],
    min_pass: u64,
    subject: Option<&str>,
    context: Option<&str>,
    session_id: &str,
) -> Session {
    let key = signing();
    let policy = GatePolicy {
        suite: "frontier".to_string(),
        cells: cells.iter().map(|(f, t)| format!("{f}:t{t}")).collect(),
        challenges: cells.len() as u64,
        min_pass,
        ttl_seconds: 300,
    };
    let mut challenges = Vec::new();
    let mut tickets = Vec::new();
    let mut instances = Vec::new();
    for (i, (family, tier)) in cells.iter().enumerate() {
        let seed = 700_000 + i as u64;
        let answer = if i % 2 == 0 { "42" } else { "17" };
        let inst = instance(family, *tier, seed, &format!("puzzle {i}"), answer);
        let opts = IssueOptions {
            family,
            tier: *tier,
            ttl_seconds: Some(300),
            context: context.map(str::to_string),
            subject: subject.map(str::to_string),
            session_id: Some(session_id.to_string()),
            holdout_pool: None,
            now: Some(at(NOW)),
        };
        let (challenge, ticket) = issue_challenge(&opts, seed, &inst, &key).unwrap();
        challenges.push(challenge);
        tickets.push(ticket);
        instances.push(inst);
    }
    Session {
        policy,
        challenges,
        tickets,
        instances,
    }
}

/// The expected answer for a session challenge index (the fabricated
/// instance's answer).
fn expected(session: &Session, i: usize) -> String {
    session.tickets[i].expected.clone()
}

fn oracle(
    instances: Vec<GeneratedInstance>,
) -> impl Fn(&str, &str, u32, u64) -> Result<GeneratedInstance, String> {
    move |suite_version, family, tier, seed| {
        instances
            .iter()
            .find(|i| {
                i.suite_version == suite_version
                    && i.family == family
                    && i.tier == tier
                    && i.seed == seed
            })
            .cloned()
            .ok_or_else(|| format!("no instance for {family}:t{tier} seed {seed}"))
    }
}

fn sign_value(value: &Value, key: &SigningKey) -> String {
    URL_SAFE_NO_PAD.encode(key.sign(canonical_json(value).as_bytes()).to_bytes())
}

fn sign_admission(body: &Value, key: &SigningKey) -> Admission {
    Admission {
        protocol: GATE_PROTOCOL.to_string(),
        payload: canonical_json(body),
        signature: sign_value(body, key),
    }
}

/// Consume a session like the TypeScript `submitSession`: every listed
/// `(index, response)` pair mints a receipt through `verify_response`, then
/// the admission body is signed by the session key.
fn decide(session: &Session, responses: &[(usize, &str)]) -> Admission {
    decide_with(session, responses, &session.policy.clone(), None)
}

/// `decide` with one session-scoped subject proof embedded in every minted
/// receipt, like `submitSession`'s shared `subjectProof`.
fn decide_proving(
    session: &Session,
    responses: &[(usize, &str)],
    proof: &SubjectProof,
) -> Admission {
    decide_with(session, responses, &session.policy.clone(), Some(proof))
}

fn decide_with(
    session: &Session,
    responses: &[(usize, &str)],
    policy: &GatePolicy,
    subject_proof: Option<&SubjectProof>,
) -> Admission {
    let key = signing();
    let mut receipts = Vec::new();
    let mut passed = 0u64;
    for &(i, response) in responses {
        let receipt = verify_response(
            &session.tickets[i],
            response,
            &session.instances[i],
            &key,
            subject_proof,
            Some(at(LATER)),
        )
        .unwrap();
        let body: ReceiptBody = serde_json::from_str(&receipt.payload).unwrap();
        if body.verdict.pass {
            passed += 1;
        }
        receipts.push(serde_json::to_value(&receipt).unwrap());
    }
    // `subject`/`context` are only present when the session carried them —
    // an explicit `null` would not survive the binding comparison.
    let mut body = json!({
        "kind": "admission",
        "sessionId": SESSION,
        "policy": serde_json::to_value(policy).unwrap(),
        "challenges": serde_json::to_value(&session.challenges).unwrap(),
        "receipts": receipts,
        "verdict": {
            "pass": passed >= policy.min_pass,
            "passed": passed,
            "required": policy.min_pass,
            "decidedAt": LATER,
        },
    });
    if let Some(subject) = &session.challenges[0].subject {
        body["subject"] = json!(subject);
    }
    if let Some(context) = &session.challenges[0].context {
        body["context"] = json!(context);
    }
    sign_admission(&body, &key)
}

fn payload(admission: &Admission) -> Value {
    serde_json::from_str(&admission.payload).unwrap()
}

fn reason(check: &AdmissionCheck) -> &str {
    check.reason.as_deref().unwrap_or("")
}

// --- policy validation ------------------------------------------------

#[test]
fn policy_parses_and_bounds_every_field() {
    let policy = GatePolicy::parse(
        &json!({"suite": "frontier", "cells": ["automata:t6", "knights:t5"], "challenges": 3, "minPass": 2, "ttlSeconds": 300}),
    )
    .unwrap();
    assert_eq!(policy.suite, "frontier");
    assert_eq!(policy.challenges, 3);
    assert_eq!(policy.min_pass, 2);
    policy.validate().unwrap();

    for bad in [
        json!(null),
        json!({"suite": "typo"}),
        json!({"suite": "frontier", "cells": [], "challenges": 1, "minPass": 1, "ttlSeconds": 30}),
        json!({"suite": "frontier", "cells": vec![json!("automata:t6"); 65], "challenges": 1, "minPass": 1, "ttlSeconds": 30}),
        json!({"suite": "frontier", "cells": ["automata:t6", "automata:t6"], "challenges": 1, "minPass": 1, "ttlSeconds": 30}),
        json!({"suite": "frontier", "cells": ["automata:t6", 7], "challenges": 1, "minPass": 1, "ttlSeconds": 30}),
        json!({"suite": "frontier", "cells": ["automata:t6"], "challenges": 0, "minPass": 1, "ttlSeconds": 30}),
        json!({"suite": "frontier", "cells": ["automata:t6"], "challenges": 17, "minPass": 1, "ttlSeconds": 30}),
        json!({"suite": "frontier", "cells": ["automata:t6"], "challenges": 2, "minPass": 0, "ttlSeconds": 30}),
        json!({"suite": "frontier", "cells": ["automata:t6"], "challenges": 2, "minPass": 3, "ttlSeconds": 30}),
        json!({"suite": "frontier", "cells": ["automata:t6"], "challenges": 2, "minPass": 1, "ttlSeconds": 9}),
        json!({"suite": "frontier", "cells": ["automata:t6"], "challenges": 2, "minPass": 1, "ttlSeconds": 3601}),
        json!({"suite": "frontier", "cells": ["automata:t6"], "challenges": 2, "minPass": 1, "ttlSeconds": "300"}),
    ] {
        assert!(GatePolicy::parse(&bad).is_err(), "accepted {bad}");
    }
}

#[test]
fn policy_rejects_malformed_cell_shapes() {
    for cell in [
        "automata",
        "automata:t",
        "automata:x6",
        "Automata:t6",
        "automata:t-1",
        ":t6",
        "automata:t6x",
        "auto mata:t6",
        "automata:6",
    ] {
        let bad = json!({"suite": "frontier", "cells": [cell], "challenges": 1, "minPass": 1, "ttlSeconds": 30});
        assert!(GatePolicy::parse(&bad).is_err(), "accepted cell {cell}");
    }
    // Documented divergence from `parsePolicy` in bench/gate.ts: a
    // well-shaped cell absent from the suite pool parses here — pool
    // membership is enforced when an embedded receipt regenerates through
    // the oracle (a receipt for a nonexistent cell fails its own check).
    let unknown = json!({"suite": "frontier", "cells": ["nosuch:t0"], "challenges": 1, "minPass": 1, "ttlSeconds": 30});
    assert!(GatePolicy::parse(&unknown).is_ok());
}

// --- valid admissions ---------------------------------------------------

#[test]
fn a_full_passing_admission_replays() {
    let session = issue_session(&[("cryptarithm", 6), ("registervm", 5)], 1);
    let admission = decide(
        &session,
        &[(0, &expected(&session, 0)), (1, &expected(&session, 1))],
    );
    let check = check_admission(&admission, oracle(session.instances.clone()));
    assert_eq!(
        check,
        AdmissionCheck {
            ok: true,
            verdict: Some(true),
            passed: Some(2),
            unreplayed: None,
            reason: None,
        }
    );
}

#[test]
fn subject_and_context_bound_admissions_replay() {
    let session = issue_session_bound(
        &[("cryptarithm", 6)],
        1,
        Some("agent-7"),
        Some("jobs-board"),
        SESSION,
    );
    let admission = decide(&session, &[(0, &expected(&session, 0))]);
    let check = check_admission(&admission, oracle(session.instances.clone()));
    assert!(check.ok, "{:?}", check.reason);
    assert_eq!(check.verdict, Some(true));
}

#[test]
fn a_wrong_answer_stays_a_truthful_failed_challenge() {
    let session = issue_session(&[("cryptarithm", 6), ("registervm", 5)], 1);
    // One correct, one canonical-but-wrong response: two receipts, one pass.
    let admission = decide(&session, &[(0, &expected(&session, 0)), (1, "0")]);
    let check = check_admission(&admission, oracle(session.instances.clone()));
    assert_eq!(check.verdict, Some(true));
    assert_eq!(check.passed, Some(1));
}

#[test]
fn min_pass_arithmetic_keeps_the_verdict_honest() {
    let session = issue_session(&[("cryptarithm", 6), ("registervm", 5)], 2);
    let admission = decide(&session, &[(0, &expected(&session, 0))]);
    let check = check_admission(&admission, oracle(session.instances.clone()));
    assert!(check.ok, "{:?}", check.reason);
    assert_eq!(check.verdict, Some(false));
    assert_eq!(check.passed, Some(1));
}

// --- envelope and payload shape -------------------------------------------

#[test]
fn envelope_and_payload_shape_are_checked_first() {
    let session = issue_session(&[("cryptarithm", 6)], 1);
    let admission = decide(&session, &[(0, &expected(&session, 0))]);
    let oracle = oracle(session.instances.clone());

    let wrong_protocol = Admission {
        protocol: ATTEST_PROTOCOL.to_string(),
        ..admission.clone()
    };
    assert_eq!(
        reason(&check_admission(&wrong_protocol, &oracle)),
        "not a gate admission"
    );

    let not_json = Admission {
        payload: "{".to_string(),
        ..admission.clone()
    };
    assert_eq!(
        reason(&check_admission(&not_json, &oracle)),
        "payload is not JSON"
    );

    let empty_body = Admission {
        payload: "{}".to_string(),
        signature: "x".to_string(),
        protocol: GATE_PROTOCOL.to_string(),
    };
    assert_eq!(
        reason(&check_admission(&empty_body, &oracle)),
        "malformed admission payload"
    );

    let mut body = payload(&admission);
    body["sessionId"] = json!("gs_short");
    assert_eq!(
        reason(&check_admission(
            &sign_admission(&body, &signing()),
            &oracle
        )),
        "malformed admission payload"
    );
}

// --- challenge-list binding (all before the signature check) --------------

#[test]
fn challenge_binding_failures_precede_the_signature() {
    let session = issue_session_bound(
        &[("cryptarithm", 6), ("registervm", 5)],
        1,
        Some("agent-7"),
        None,
        SESSION,
    );
    let admission = decide(
        &session,
        &[(0, &expected(&session, 0)), (1, &expected(&session, 1))],
    );
    // No re-signing: each failure must fire before the signature is checked.
    let oracle = oracle(session.instances.clone());
    let check = |body: &Value| {
        check_admission(
            &Admission {
                protocol: GATE_PROTOCOL.to_string(),
                payload: canonical_json(body),
                signature: "AAAA".to_string(),
            },
            &oracle,
        )
    };

    let mut body = payload(&admission);
    body["challenges"] = json!([body["challenges"][0].clone()]);
    assert_eq!(
        reason(&check(&body)),
        "challenge list does not cover the policy"
    );

    let mut body = payload(&admission);
    body["policy"]["minPass"] = json!(99);
    assert!(reason(&check(&body)).starts_with("invalid embedded policy:"));

    let mut body = payload(&admission);
    body["challenges"][1]["sessionId"] = json!("gs_bbbbbbbbbbbb");
    assert_eq!(
        reason(&check(&body)),
        "challenge is not bound to this session"
    );

    let mut body = payload(&admission);
    body["challenges"][0]["suiteVersion"] = json!(V2_SUITE_VERSION);
    assert_eq!(
        reason(&check(&body)),
        "challenge suite disagrees with the policy"
    );

    let mut body = payload(&admission);
    body["challenges"][0]["family"] = json!("automata");
    assert_eq!(
        reason(&check(&body)),
        "challenge cell is outside the policy"
    );

    let mut body = payload(&admission);
    body["challenges"][1]["expiresAt"] = json!("2026-09-18T00:06:00Z");
    assert_eq!(
        reason(&check(&body)),
        "session challenges do not share one deadline"
    );

    let mut body = payload(&admission);
    body["challenges"][1]["verifier"]["publicKey"] =
        json!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    assert_eq!(
        reason(&check(&body)),
        "session challenges mix verifier keys"
    );

    let mut body = payload(&admission);
    body["challenges"][0]["verifier"]["keyId"] = json!("0000000000000000");
    assert_eq!(
        reason(&check(&body)),
        "verifier keyId does not match the public key"
    );

    let mut body = payload(&admission);
    body["challenges"][0]["subject"] = json!("agent-9");
    assert_eq!(
        reason(&check(&body)),
        "challenge binding disagrees with the admission"
    );

    let mut body = payload(&admission);
    let first_id = body["challenges"][0]["challengeId"].clone();
    body["challenges"][1]["challengeId"] = first_id;
    assert_eq!(reason(&check(&body)), "duplicate challenge id");
}

// --- signature ------------------------------------------------------------

#[test]
fn a_bad_signature_fails() {
    let session = issue_session(&[("cryptarithm", 6)], 1);
    let admission = decide(&session, &[(0, &expected(&session, 0))]);
    let mut bad = admission.clone();
    bad.signature = format!(
        "{}AAAA",
        &admission.signature[..admission.signature.len() - 4]
    );
    assert_eq!(
        reason(&check_admission(&bad, oracle(session.instances.clone()))),
        "signature does not verify"
    );
}

#[test]
fn a_payload_resigned_under_a_foreign_key_fails() {
    let session = issue_session(&[("cryptarithm", 6)], 1);
    let admission = decide(&session, &[(0, &expected(&session, 0))]);
    let other = SigningKey::from_bytes(&[9u8; 32]);
    let resigned = sign_admission(&payload(&admission), &other);
    assert_eq!(
        reason(&check_admission(
            &resigned,
            oracle(session.instances.clone())
        )),
        "signature does not verify"
    );
}

// --- receipts ---------------------------------------------------------------

#[test]
fn a_receipt_from_another_session_does_not_graft_on() {
    let a = issue_session(&[("cryptarithm", 6)], 1);
    let b = issue_session_bound(&[("cryptarithm", 6)], 1, None, None, "gs_bbbbbbbbbbbb");
    let admission_a = decide(&a, &[(0, &expected(&a, 0))]);
    let receipt_b = verify_response(
        &b.tickets[0],
        &expected(&b, 0),
        &b.instances[0],
        &signing(),
        None,
        Some(at(LATER)),
    )
    .unwrap();
    let mut body = payload(&admission_a);
    body["receipts"] = json!([serde_json::to_value(&receipt_b).unwrap()]);
    let grafted = sign_admission(&body, &signing());
    let instances = [a.instances.clone(), b.instances.clone()].concat();
    assert_eq!(
        reason(&check_admission(&grafted, oracle(instances))),
        "receipt is not for a listed session challenge"
    );
}

#[test]
fn two_receipts_for_one_challenge_fail() {
    let session = issue_session(&[("cryptarithm", 6), ("registervm", 5)], 1);
    let admission = decide(&session, &[(0, &expected(&session, 0))]);
    let mut body = payload(&admission);
    let first = body["receipts"][0].clone();
    body["receipts"] = json!([first.clone(), first]);
    let doubled = sign_admission(&body, &signing());
    assert_eq!(
        reason(&check_admission(
            &doubled,
            oracle(session.instances.clone())
        )),
        "two receipts for one challenge"
    );
}

#[test]
fn more_receipts_than_challenges_is_malformed() {
    let session = issue_session(&[("cryptarithm", 6)], 1);
    let admission = decide(&session, &[(0, &expected(&session, 0))]);
    let mut body = payload(&admission);
    let first = body["receipts"][0].clone();
    body["receipts"] = json!([first.clone(), first]);
    let over = sign_admission(&body, &signing());
    assert_eq!(
        reason(&check_admission(&over, oracle(session.instances.clone()))),
        "malformed receipts"
    );
}

#[test]
fn an_embedded_receipt_that_does_not_verify_fails() {
    let session = issue_session(&[("cryptarithm", 6)], 1);
    let admission = decide(&session, &[(0, &expected(&session, 0))]);
    let mut body = payload(&admission);
    let mut receipt = body["receipts"][0].clone();
    let sig = receipt["signature"].as_str().unwrap().to_string();
    receipt["signature"] = json!(format!("{}AAAA", &sig[..sig.len() - 4]));
    body["receipts"] = json!([receipt]);
    let bad = sign_admission(&body, &signing());
    let check = check_admission(&bad, oracle(session.instances.clone()));
    assert!(
        reason(&check).starts_with("embedded receipt does not verify:"),
        "{:?}",
        check.reason
    );
}

// --- subject binding: one subject key per session ------------------------------

#[test]
fn proofed_receipts_share_one_subject_key_and_replay() {
    let session = issue_session(&[("cryptarithm", 6), ("registervm", 5)], 1);
    let respondent = generate_verifier();
    // Session-scoped: one proof object embeds in every minted receipt.
    let proof = subject_proof_for(&session.challenges[0], &respondent).unwrap();
    let admission = decide_proving(
        &session,
        &[(0, &expected(&session, 0)), (1, &expected(&session, 1))],
        &proof,
    );
    let check = check_admission(&admission, oracle(session.instances.clone()));
    assert!(check.ok, "{:?}", check.reason);
    assert_eq!(check.passed, Some(2));
}

#[test]
fn receipts_mixing_subject_keys_fail() {
    let session = issue_session(&[("cryptarithm", 6), ("registervm", 5)], 1);
    let key = signing();
    // Same session transcript scope, different respondent keys: each proof
    // verifies for its own receipt, but an admission binds one subject.
    let mut receipts = Vec::new();
    for (i, respondent) in [generate_verifier(), generate_verifier()]
        .iter()
        .enumerate()
    {
        let proof = subject_proof_for(&session.challenges[i], respondent).unwrap();
        let receipt = verify_response(
            &session.tickets[i],
            &expected(&session, i),
            &session.instances[i],
            &key,
            Some(&proof),
            Some(at(LATER)),
        )
        .unwrap();
        receipts.push(serde_json::to_value(&receipt).unwrap());
    }
    let body = json!({
        "kind": "admission",
        "sessionId": SESSION,
        "policy": serde_json::to_value(&session.policy).unwrap(),
        "challenges": serde_json::to_value(&session.challenges).unwrap(),
        "receipts": receipts,
        "verdict": {"pass": true, "passed": 2, "required": 1, "decidedAt": LATER},
    });
    let admission = sign_admission(&body, &key);
    assert_eq!(
        reason(&check_admission(
            &admission,
            oracle(session.instances.clone())
        )),
        "receipts mix subject keys"
    );
}

#[test]
fn a_proofed_receipt_coexists_with_unproofed_ones() {
    let session = issue_session(&[("cryptarithm", 6), ("registervm", 5)], 1);
    let key = signing();
    let proof = subject_proof_for(&session.challenges[0], &generate_verifier()).unwrap();
    let proofed = verify_response(
        &session.tickets[0],
        &expected(&session, 0),
        &session.instances[0],
        &key,
        Some(&proof),
        Some(at(LATER)),
    )
    .unwrap();
    let unproofed = verify_response(
        &session.tickets[1],
        &expected(&session, 1),
        &session.instances[1],
        &key,
        None,
        Some(at(LATER)),
    )
    .unwrap();
    let body = json!({
        "kind": "admission",
        "sessionId": SESSION,
        "policy": serde_json::to_value(&session.policy).unwrap(),
        "challenges": serde_json::to_value(&session.challenges).unwrap(),
        "receipts": [
            serde_json::to_value(&proofed).unwrap(),
            serde_json::to_value(&unproofed).unwrap(),
        ],
        "verdict": {"pass": true, "passed": 2, "required": 1, "decidedAt": LATER},
    });
    let admission = sign_admission(&body, &key);
    let check = check_admission(&admission, oracle(session.instances.clone()));
    assert!(check.ok, "{:?}", check.reason);
    assert_eq!(check.passed, Some(2));
}

#[test]
fn a_present_but_malformed_proof_fails_inside_the_receipt_check() {
    let session = issue_session(&[("cryptarithm", 6)], 1);
    let admission = decide(&session, &[(0, &expected(&session, 0))]);
    let mut body = payload(&admission);
    let mut receipt = body["receipts"][0].clone();
    // `subjectProof: null` is present (`!== undefined`) but not well-formed —
    // the embedded receipt check reports it before the subject-key rule.
    let mut receipt_payload: Value =
        serde_json::from_str(receipt["payload"].as_str().unwrap()).unwrap();
    receipt_payload["subjectProof"] = json!(null);
    receipt["payload"] = json!(canonical_json(&receipt_payload));
    receipt["signature"] = json!(sign_value(&receipt_payload, &signing()));
    body["receipts"] = json!([receipt]);
    let bad = sign_admission(&body, &signing());
    assert_eq!(
        reason(&check_admission(&bad, oracle(session.instances.clone()))),
        "embedded receipt does not verify: malformed subject proof"
    );
}

// --- verdict and deadline ---------------------------------------------------

#[test]
fn verdict_arithmetic_is_recomputed() {
    let session = issue_session(&[("cryptarithm", 6), ("registervm", 5)], 1);
    let admission = decide(
        &session,
        &[(0, &expected(&session, 0)), (1, &expected(&session, 1))],
    );
    for (member, value) in [
        ("passed", json!(0)),
        ("required", json!(2)),
        ("pass", json!(false)),
    ] {
        let mut body = payload(&admission);
        body["verdict"][member] = value;
        let tampered = sign_admission(&body, &signing());
        assert_eq!(
            reason(&check_admission(
                &tampered,
                oracle(session.instances.clone())
            )),
            "verdict does not rescore"
        );
    }
}

#[test]
fn a_decision_after_the_deadline_fails() {
    let session = issue_session(&[("cryptarithm", 6)], 1);
    let admission = decide(&session, &[(0, &expected(&session, 0))]);
    let mut body = payload(&admission);
    body["verdict"]["decidedAt"] = json!("2026-09-18T00:06:00Z");
    let late = sign_admission(&body, &signing());
    assert_eq!(
        reason(&check_admission(&late, oracle(session.instances.clone()))),
        "decision is later than the session deadline"
    );
}

// --- forward compatibility ----------------------------------------------------

#[test]
fn unknown_challenge_members_are_tolerated() {
    let session = issue_session(&[("cryptarithm", 6)], 1);
    // A listed challenge carrying a future member: the receipt embeds the
    // same extended challenge, so the canonical comparison still holds.
    let mut challenge = serde_json::to_value(&session.challenges[0]).unwrap();
    challenge["futureCapability"] = json!({"anything": true});
    let receipt_body = json!({
        "kind": "receipt",
        "challenge": challenge.clone(),
        "seed": 700_000,
        "expected": "42",
        "response": "42",
        "verdict": {"pass": true, "format": "integer", "answeredAt": LATER},
    });
    let receipt = json!({
        "protocol": ATTEST_PROTOCOL,
        "payload": canonical_json(&receipt_body),
        "signature": sign_value(&receipt_body, &signing()),
    });
    let body = json!({
        "kind": "admission",
        "sessionId": SESSION,
        "policy": serde_json::to_value(&session.policy).unwrap(),
        "challenges": [challenge],
        "receipts": [receipt],
        "verdict": {"pass": true, "passed": 1, "required": 1, "decidedAt": LATER},
    });
    let admission = sign_admission(&body, &signing());
    let check = check_admission(&admission, oracle(session.instances.clone()));
    assert!(check.ok, "{:?}", check.reason);
    assert_eq!(check.passed, Some(1));
}

// --- TypeScript interop: admissions minted by bench/gate.ts -------------------

#[test]
fn typescript_issued_admissions_replay() {
    for (fixture, verdict, passed) in [
        ("tests/fixtures/ts_admission_pass.json", true, 3),
        ("tests/fixtures/ts_admission_fail.json", false, 1),
        // Every receipt carries the same session-scoped `subjectProof`.
        ("tests/fixtures/ts_admission_subject.json", true, 3),
    ] {
        let text = std::fs::read_to_string(fixture).expect("fixture missing");
        let fixture: Value = serde_json::from_str(&text).expect("fixture parses");
        let admission: Admission =
            serde_json::from_value(fixture["admission"].clone()).expect("admission parses");
        let instances: Vec<GeneratedInstance> =
            serde_json::from_value(fixture["instances"].clone()).expect("instances parse");
        let check = check_admission(&admission, oracle(instances));
        assert!(check.ok, "{fixture} failed: {:?}", check.reason);
        assert_eq!(check.verdict, Some(verdict), "{fixture}");
        assert_eq!(check.passed, Some(passed), "{fixture}");
    }
}
