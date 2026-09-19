//! Badge (clankdar-badge-v1) tests: subject-signed dossiers of
//! subject-bound admissions, optional tlog inclusion proofs, holdout pool
//! disclosure, and malformed-member handling.
//!
//! `ts_badge_*.json` fixtures are minted by the TypeScript reference
//! (`bench/badge.ts` in the clankdar repository); each carries the
//! generator instances its receipts replay so no clankdar checkout is
//! needed. Fabricated badges mint sessions through the library
//! `issue_session`/`submit_session` under a deterministic fake generator —
//! every response derives from `ticket.expected` at runtime, never a
//! literal answer.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};
use std::collections::HashMap;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use valhalla_clankdar_attest_prototype::*;

const NOW: &str = "2026-09-18T00:00:00Z";
const LATER: &str = "2026-09-18T00:01:00Z";

fn at(iso: &str) -> OffsetDateTime {
    OffsetDateTime::parse(iso, &Rfc3339).unwrap()
}

/// Distinct fixed keys: the badge subject, a second subject, and two
/// issuers — a badge may aggregate admissions across verifier keys.
fn subject() -> SigningKey {
    SigningKey::from_bytes(&[11u8; 32])
}

fn stranger() -> SigningKey {
    SigningKey::from_bytes(&[22u8; 32])
}

fn issuer_a() -> SigningKey {
    SigningKey::from_bytes(&[7u8; 32])
}

fn issuer_b() -> SigningKey {
    SigningKey::from_bytes(&[9u8; 32])
}

/// `subject_proof_for` takes the respondent key as a JWK — the same OKP
/// shape `generate_verifier` mints.
fn jwk_of(key: &SigningKey) -> VerifierJwk {
    VerifierJwk {
        kty: "OKP".to_string(),
        crv: "Ed25519".to_string(),
        x: URL_SAFE_NO_PAD.encode(key.verifying_key().to_bytes()),
        d: URL_SAFE_NO_PAD.encode(key.to_bytes()),
    }
}

/// The fake generator: prompt and answer derive from the seed, so the
/// same closure serves issuance, submission, and the independent replay.
fn fake_oracle(
    suite_version: &str,
    family: &str,
    tier: u32,
    seed: u64,
) -> Result<GeneratedInstance, String> {
    match family {
        "cryptarithm" | "registervm" => Ok(GeneratedInstance {
            suite_version: suite_version.to_string(),
            family: family.to_string(),
            tier,
            seed,
            prompt: format!("{family} puzzle t{tier} for seed {seed}"),
            answer: format!("{}", seed % 1_000_000),
        }),
        _ => Err(format!("no instance for {family}:t{tier} seed {seed}")),
    }
}

fn fixture(name: &str) -> Value {
    let text = std::fs::read_to_string(format!("tests/fixtures/{name}")).expect("fixture missing");
    serde_json::from_str(&text).expect("fixture parses")
}

/// The generator oracle backed by the fixture's recorded instances — the
/// same lookup the gate/tlog fixture tests use.
fn fixture_oracle(
    fixture: &Value,
) -> impl Fn(&str, &str, u32, u64) -> Result<GeneratedInstance, String> + '_ {
    let instances: Vec<GeneratedInstance> =
        serde_json::from_value(fixture["instances"].clone()).unwrap_or_default();
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

fn reason(check: &BadgeCheck) -> &str {
    check.reason.as_deref().unwrap_or_default()
}

/// Sign `body` like `packBadge`: canonical JSON under the subject key.
fn badge_of(body: &Value, key: &SigningKey) -> Value {
    let payload = canonical_json(body);
    json!({
        "protocol": BADGE_PROTOCOL,
        "payload": payload,
        "signature": URL_SAFE_NO_PAD.encode(key.sign(payload.as_bytes()).to_bytes()),
    })
}

fn badge_body(admissions: &[Admission], key: &SigningKey) -> Value {
    json!({
        "kind": "badge",
        "subjectKey": URL_SAFE_NO_PAD.encode(key.verifying_key().to_bytes()),
        "admissions": admissions,
        "issuedAt": LATER,
    })
}

/// A real subject-bound admission minted in Rust: `issue_session` +
/// `submit_session` carrying a session-scoped proof for `subject_key`.
/// `correct` counts how many challenges get the right response (derived
/// from the ticket's expected answer — never a literal); the rest get a
/// wrong-but-canonical one, so `min_pass` decides the recorded verdict.
fn bound_admission(
    issuer: &SigningKey,
    subject_key: &SigningKey,
    challenges: u64,
    min_pass: u64,
    correct: usize,
    seed_base: u64,
) -> Admission {
    let policy = GatePolicy {
        suite: "frontier".to_string(),
        cells: vec!["cryptarithm:t6".to_string(), "registervm:t5".to_string()],
        challenges,
        min_pass,
        ttl_seconds: 300,
    };
    let pick = |bound: usize| bound.saturating_sub(1);
    let (session, _) = issue_session(
        &policy,
        &IssueSessionOptions {
            subject: None,
            context: None,
            pool: None,
            now: Some(at(NOW)),
            pick: Some(&pick),
            seed_base: Some(seed_base),
        },
        issuer,
        fake_oracle,
    )
    .expect("session issues");
    let proof =
        subject_proof_for(&session.tickets[0].challenge, &jwk_of(subject_key)).expect("proof");
    let responses: HashMap<String, String> = session
        .tickets
        .iter()
        .enumerate()
        .map(|(i, ticket)| {
            let response = if i < correct {
                ticket.expected.clone()
            } else {
                // A canonical-but-wrong answer derived from the expected
                // one: bump the integer, or fall back to a string the
                // family cannot accept.
                ticket
                    .expected
                    .parse::<u64>()
                    .map(|n| format!("{}", n + 1))
                    .unwrap_or_else(|_| format!("{}x", ticket.expected))
            };
            (ticket.challenge.challenge_id.clone(), response)
        })
        .collect();
    let (_receipts, admission) = submit_session(
        &session,
        &responses,
        &SubmitSessionOptions {
            subject_proof: Some(&proof),
            pool: None,
            now: Some(at(LATER)),
        },
        issuer,
        fake_oracle,
    )
    .expect("session submits");
    admission
}

/// An admission with no subject proof at all — valid, just unbound.
fn unbound_admission(issuer: &SigningKey, seed_base: u64) -> Admission {
    let policy = GatePolicy {
        suite: "frontier".to_string(),
        cells: vec!["cryptarithm:t6".to_string()],
        challenges: 1,
        min_pass: 1,
        ttl_seconds: 300,
    };
    let (session, _) = issue_session(
        &policy,
        &IssueSessionOptions {
            subject: None,
            context: None,
            pool: None,
            now: Some(at(NOW)),
            pick: None,
            seed_base: Some(seed_base),
        },
        issuer,
        fake_oracle,
    )
    .expect("session issues");
    let responses: HashMap<String, String> = session
        .tickets
        .iter()
        .map(|t| (t.challenge.challenge_id.clone(), t.expected.clone()))
        .collect();
    let (_receipts, admission) = submit_session(
        &session,
        &responses,
        &SubmitSessionOptions {
            subject_proof: None,
            pool: None,
            now: Some(at(LATER)),
        },
        issuer,
        fake_oracle,
    )
    .expect("session submits");
    admission
}

// --- TypeScript-minted fixtures ------------------------------------------------

#[test]
fn a_multi_issuer_badge_checks() {
    let fixture = fixture("ts_badge_multi_issuer.json");
    let check = check_badge(&fixture["badge"], None, fixture_oracle(&fixture));
    assert!(check.ok, "{:?}", check.reason);
    assert_eq!(check.subject.as_deref(), fixture["subject"].as_str());
    assert_eq!(check.admissions, Some(2));
    // Both recorded verdicts are `pass` — passed counts verdicts, not receipts.
    assert_eq!(check.passed, Some(2));
    assert_eq!(check.logged, Some(0));
    assert_eq!(check.unreplayed, None);
}

#[test]
fn held_out_scores_are_issuer_claimed_until_the_pool_is_disclosed() {
    let fixture = fixture("ts_badge_holdout.json");
    let pool: HoldoutPool = serde_json::from_value(fixture["pool"].clone()).expect("pool parses");

    // Without the pool both receipts verify but their scores stay
    // issuer-claimed — the badge surfaces them in `unreplayed`.
    let without = check_badge(&fixture["badge"], None, fixture_oracle(&fixture));
    assert!(without.ok, "{:?}", without.reason);
    assert_eq!(without.admissions, Some(1));
    assert_eq!(without.unreplayed, Some(2));

    // Disclosing the committed pool replays the hidden stream fully.
    let with = check_badge(
        &fixture["badge"],
        Some(std::slice::from_ref(&pool)),
        fixture_oracle(&fixture),
    );
    assert!(with.ok, "{:?}", with.reason);
    assert_eq!(with.unreplayed, None);

    // A different pool — even a valid one — is no better than none.
    let foreign = HoldoutPool {
        protocol: HOLDOUT_PROTOCOL.to_string(),
        suite: "frontier".to_string(),
        cells: vec![HoldoutCell {
            family: "sat".to_string(),
            tier: 4,
            label: "held-out-secret-label-other".to_string(),
        }],
        pool_key: pool_key_of(
            "frontier",
            &[HoldoutCell {
                family: "sat".to_string(),
                tier: 4,
                label: "held-out-secret-label-other".to_string(),
            }],
        ),
    };
    let mismatched = check_badge(
        &fixture["badge"],
        Some(std::slice::from_ref(&foreign)),
        fixture_oracle(&fixture),
    );
    assert!(mismatched.ok, "{:?}", mismatched.reason);
    assert_eq!(mismatched.unreplayed, Some(2));
}

#[test]
fn tlog_proofs_log_the_sessions_they_cover() {
    let fixture = fixture("ts_badge_logged.json");
    let check = check_badge(&fixture["badge"], None, fixture_oracle(&fixture));
    assert!(check.ok, "{:?}", check.reason);
    assert_eq!(check.admissions, Some(3));
    assert_eq!(check.passed, Some(3));
    // Two of the three carried sessions have verified inclusion proofs.
    assert_eq!(check.logged, Some(2));
}

#[test]
fn malformed_members_fail_without_panicking() {
    let fixture = fixture("ts_badge_malformed_members.json");
    for badge in fixture["badges"].as_array().expect("badges array") {
        // No receipts ever replay — the member shape fails first — so the
        // oracle is never consulted.
        let check = check_badge(badge, None, |_, f, t, s| {
            Err(format!("oracle should not run for {f}:t{t} seed {s}"))
        });
        assert!(!check.ok);
        assert_eq!(
            reason(&check),
            "admission does not verify: not a gate admission",
            "badge {badge}"
        );
    }
}

#[test]
fn a_member_bound_to_a_different_subject_fails() {
    let fixture = fixture("ts_badge_wrong_subject.json");
    let check = check_badge(&fixture["badge"], None, fixture_oracle(&fixture));
    assert!(!check.ok);
    assert_eq!(reason(&check), "admission is bound to a different subject");
}

#[test]
fn a_tampered_signature_fails() {
    let fixture = fixture("ts_badge_tampered_signature.json");
    let check = check_badge(&fixture["badge"], None, fixture_oracle(&fixture));
    assert!(!check.ok);
    assert_eq!(reason(&check), "badge signature does not verify");
}

#[test]
fn an_undecided_session_is_not_a_logged_decision() {
    let fixture = fixture("ts_badge_undecided_proof.json");
    let check = check_badge(&fixture["badge"], None, fixture_oracle(&fixture));
    assert!(!check.ok);
    assert_eq!(reason(&check), "proof has no logged decision");
}

// --- Fabricated badges ---------------------------------------------------------

#[test]
fn pack_badge_round_trips_across_issuers() {
    let subject = subject();
    let a = bound_admission(&issuer_a(), &subject, 2, 1, 2, 700_000);
    let b = bound_admission(&issuer_b(), &subject, 2, 1, 2, 800_000);
    let admissions = [a, b];
    let badge = pack_badge(
        &admissions,
        &PackBadgeOptions {
            proofs: None,
            pools: None,
            now: Some(at(LATER)),
        },
        &subject,
        fake_oracle,
    )
    .expect("badge packs");
    assert_eq!(badge.protocol, BADGE_PROTOCOL);
    let value = serde_json::to_value(&badge).expect("serializes");
    let check = check_badge(&value, None, fake_oracle);
    assert!(check.ok, "{:?}", check.reason);
    assert_eq!(check.admissions, Some(2));
    assert_eq!(check.passed, Some(2));
    assert_eq!(check.logged, Some(0));
}

#[test]
fn passed_counts_recorded_verdicts_not_receipts() {
    let subject = subject();
    // `correct < min_pass` mints a valid admission whose verdict is fail.
    let failing = bound_admission(&issuer_a(), &subject, 2, 2, 1, 700_000);
    let passing = bound_admission(&issuer_b(), &subject, 2, 1, 2, 800_000);
    let badge = badge_of(
        &badge_body(&[failing.clone(), passing.clone()], &subject),
        &subject,
    );
    let check = check_badge(&badge, None, fake_oracle);
    assert!(check.ok, "{:?}", check.reason);
    assert_eq!(check.admissions, Some(2));
    assert_eq!(check.passed, Some(1));
}

#[test]
fn envelope_and_body_shape_fail_structurally() {
    let subject = subject();
    let admission = bound_admission(&issuer_a(), &subject, 1, 1, 1, 700_000);
    let body = badge_body(std::slice::from_ref(&admission), &subject);
    let good = badge_of(&body, &subject);
    assert!(check_badge(&good, None, fake_oracle).ok);

    for (case, expected) in [
        (json!(null), "not a badge"),
        (json!("x"), "not a badge"),
        (
            json!({"protocol": "clankdar-attest-v1", "payload": "{}", "signature": "s"}),
            "not a badge",
        ),
        (
            json!({"protocol": BADGE_PROTOCOL, "payload": 7, "signature": "s"}),
            "not a badge",
        ),
        (
            json!({"protocol": BADGE_PROTOCOL, "payload": "!!!", "signature": "s"}),
            "payload is not JSON",
        ),
        (
            json!({"protocol": BADGE_PROTOCOL, "payload": "5", "signature": "s"}),
            "malformed badge payload",
        ),
    ] {
        let check = check_badge(&case, None, fake_oracle);
        assert!(!check.ok, "{case} passed");
        assert_eq!(reason(&check), expected, "{case}");
    }

    // Body-level failures reuse the good envelope shape.
    for (mutant, expected) in [
        (
            json!({"kind": "admission", "subjectKey": "x", "admissions": [], "issuedAt": LATER}),
            "malformed badge payload",
        ),
        (
            json!({"kind": "badge", "admissions": [], "issuedAt": LATER}),
            "malformed badge payload",
        ),
        (
            json!({"kind": "badge", "subjectKey": "!!!", "admissions": [1], "issuedAt": LATER}),
            "subjectKey is not an Ed25519 public key",
        ),
        (
            json!({"kind": "badge", "subjectKey": body["subjectKey"].clone(), "admissions": [], "issuedAt": LATER}),
            "admissions must be 1..64 signed admissions",
        ),
        (
            json!({"kind": "badge", "subjectKey": body["subjectKey"].clone(), "admissions": 7, "issuedAt": LATER}),
            "admissions must be 1..64 signed admissions",
        ),
    ] {
        let badge = badge_of(&mutant, &subject);
        let check = check_badge(&badge, None, fake_oracle);
        assert!(!check.ok, "{mutant} passed");
        assert_eq!(reason(&check), expected, "{mutant}");
    }
}

#[test]
fn the_admission_bound_is_enforced() {
    let subject = subject();
    let admission = bound_admission(&issuer_a(), &subject, 1, 1, 1, 700_000);
    // 65 admissions exceed the bound even before any replay.
    let mut body = badge_body(std::slice::from_ref(&admission), &subject);
    body["admissions"] = json!(vec![serde_json::to_value(&admission).unwrap(); 65]);
    let badge = badge_of(&body, &subject);
    let check = check_badge(&badge, None, fake_oracle);
    assert!(!check.ok);
    assert_eq!(reason(&check), "admissions must be 1..64 signed admissions");
}

#[test]
fn two_admissions_sharing_a_session_fail() {
    let subject = subject();
    let admission = bound_admission(&issuer_a(), &subject, 1, 1, 1, 700_000);
    let badge = badge_of(
        &badge_body(&[admission.clone(), admission], &subject),
        &subject,
    );
    let check = check_badge(&badge, None, fake_oracle);
    assert!(!check.ok);
    assert_eq!(reason(&check), "two admissions share a session");
}

#[test]
fn an_unbound_admission_fails_subject_binding() {
    let subject = subject();
    // A valid admission carrying no subject proof is not bound at all.
    let admission = unbound_admission(&issuer_a(), 700_000);
    let badge = badge_of(
        &badge_body(std::slice::from_ref(&admission), &subject),
        &subject,
    );
    let check = check_badge(&badge, None, fake_oracle);
    assert!(!check.ok);
    assert_eq!(reason(&check), "admission is not subject-bound");
}

#[test]
fn proof_member_failures_are_structured() {
    let fixture = fixture("ts_badge_logged.json");
    let badge = fixture["badge"].clone();
    let mut body: Value = serde_json::from_str(badge["payload"].as_str().unwrap()).unwrap();

    // Every malformed entry shape fails the same structured way; the
    // checks fire before the badge signature, so the stale signature on
    // the mutated payload never matters.
    for proof in [
        json!(null),
        json!("x"),
        json!({}),
        json!({"proof": {}}),
        json!({"proof": {"sessionId": 7}}),
    ] {
        body["proofs"] = json!([proof]);
        let mutant = json!({"protocol": BADGE_PROTOCOL, "payload": canonical_json(&body), "signature": badge["signature"]});
        let check = check_badge(&mutant, None, fixture_oracle(&fixture));
        assert!(!check.ok, "{proof} passed");
        assert_eq!(reason(&check), "malformed inclusion proof", "{proof}");
    }

    // `proofs` present but not an array.
    for value in [json!(null), json!(7), json!({}), json!("x")] {
        body["proofs"] = value;
        let mutant = json!({"protocol": BADGE_PROTOCOL, "payload": canonical_json(&body), "signature": badge["signature"]});
        let check = check_badge(&mutant, None, fixture_oracle(&fixture));
        assert!(!check.ok);
        assert_eq!(reason(&check), "proofs is not an array");
    }

    // A proof naming a session the badge does not carry.
    let mut body: Value = serde_json::from_str(badge["payload"].as_str().unwrap()).unwrap();
    body["proofs"] = json!([{
        "log": body["proofs"][0]["log"].clone(),
        "proof": {"sessionId": "gs_doesnotexist"},
    }]);
    let mutant = json!({"protocol": BADGE_PROTOCOL, "payload": canonical_json(&body), "signature": badge["signature"]});
    let check = check_badge(&mutant, None, fixture_oracle(&fixture));
    assert!(!check.ok);
    assert_eq!(
        reason(&check),
        "proof names a session the badge does not carry"
    );

    // A proof whose recorded index disagrees with a fresh proveSession.
    let mut body: Value = serde_json::from_str(badge["payload"].as_str().unwrap()).unwrap();
    body["proofs"][0]["proof"]["sessionIndex"] = json!(99);
    let mutant = json!({"protocol": BADGE_PROTOCOL, "payload": canonical_json(&body), "signature": badge["signature"]});
    let check = check_badge(&mutant, None, fixture_oracle(&fixture));
    assert!(!check.ok);
    assert_eq!(reason(&check), "inclusion proof does not match the log");

    // `decisionIndex !== expected.decisionIndex` is strict: a garbage,
    // null (the fixture's sessions are decided, so `null` mismatches a
    // real decision index), or boolean member never silently passes.
    for mutant_value in [json!("x"), json!(null), json!(false)] {
        let mut body: Value = serde_json::from_str(badge["payload"].as_str().unwrap()).unwrap();
        body["proofs"][0]["proof"]["decisionIndex"] = mutant_value.clone();
        let mutant = json!({"protocol": BADGE_PROTOCOL, "payload": canonical_json(&body), "signature": badge["signature"]});
        let check = check_badge(&mutant, None, fixture_oracle(&fixture));
        assert!(!check.ok, "{mutant_value} passed");
        assert_eq!(reason(&check), "inclusion proof does not match the log");
    }
    // Absent entirely — `undefined !== index` in the reference checker.
    let mut body: Value = serde_json::from_str(badge["payload"].as_str().unwrap()).unwrap();
    body["proofs"][0]["proof"]
        .as_object_mut()
        .unwrap()
        .remove("decisionIndex");
    let mutant = json!({"protocol": BADGE_PROTOCOL, "payload": canonical_json(&body), "signature": badge["signature"]});
    let check = check_badge(&mutant, None, fixture_oracle(&fixture));
    assert!(!check.ok);
    assert_eq!(reason(&check), "inclusion proof does not match the log");

    // A log that fails its own check surfaces through the proof arm.
    let mut body: Value = serde_json::from_str(badge["payload"].as_str().unwrap()).unwrap();
    body["proofs"][0]["log"]["entries"][0]["entryHash"] = json!("f".repeat(64));
    let mutant = json!({"protocol": BADGE_PROTOCOL, "payload": canonical_json(&body), "signature": badge["signature"]});
    let check = check_badge(&mutant, None, fixture_oracle(&fixture));
    assert!(!check.ok);
    assert!(
        reason(&check).starts_with("inclusion proof does not verify:"),
        "{:?}",
        check.reason
    );
}

#[test]
fn issued_at_and_signature_are_checked_last() {
    let subject = subject();
    let admission = bound_admission(&issuer_a(), &subject, 1, 1, 1, 700_000);

    // A missing or malformed issuedAt fails after the admissions replay.
    for issued_at in [json!(null), json!("not a timestamp"), json!(7)] {
        let mut body = badge_body(std::slice::from_ref(&admission), &subject);
        body["issuedAt"] = issued_at;
        let badge = badge_of(&body, &subject);
        let check = check_badge(&badge, None, fake_oracle);
        assert!(!check.ok);
        assert_eq!(reason(&check), "issuedAt is malformed");
    }

    // A badge signed by a different key than `subjectKey` claims.
    let body = badge_body(std::slice::from_ref(&admission), &subject);
    let badge = badge_of(&body, &stranger());
    let check = check_badge(&badge, None, fake_oracle);
    assert!(!check.ok);
    assert_eq!(reason(&check), "badge signature does not verify");
}

#[test]
fn pool_lists_are_bounded_validated_and_deduplicated() {
    let fixture = fixture("ts_badge_holdout.json");
    let pool: HoldoutPool = serde_json::from_value(fixture["pool"].clone()).expect("pool parses");

    // The same poolKey twice is refused, whatever the cell lists say.
    let check = check_badge(
        &fixture["badge"],
        Some(&[pool.clone(), pool.clone()]),
        fixture_oracle(&fixture),
    );
    assert!(!check.ok);
    assert_eq!(reason(&check), "two holdout pools share a poolKey");

    // More than 64 disclosed pools are refused outright.
    let pools = vec![pool.clone(); 65];
    let check = check_badge(&fixture["badge"], Some(&pools), fixture_oracle(&fixture));
    assert!(!check.ok);
    assert_eq!(reason(&check), "pools exceed the admission bound");

    // A pool whose commitment no longer matches its cells — like a typed
    // pool mutated after minting — fails the re-parse inside the check.
    let mut broken = pool.clone();
    broken.cells.push(HoldoutCell {
        family: "registervm".to_string(),
        tier: 5,
        label: "held-out-secret-label-extra".to_string(),
    });
    let check = check_badge(
        &fixture["badge"],
        Some(std::slice::from_ref(&broken)),
        fixture_oracle(&fixture),
    );
    assert!(!check.ok);
    assert!(
        reason(&check).starts_with("holdout pool does not verify:"),
        "{:?}",
        check.reason
    );
}
