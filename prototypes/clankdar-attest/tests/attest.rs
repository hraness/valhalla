//! Protocol and scorer-parity tests for the clankdar-attest prototype.

use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use valhalla_clankdar_attest_prototype::*;

fn at(iso: &str) -> OffsetDateTime {
    OffsetDateTime::parse(iso, &Rfc3339).unwrap()
}

fn instance(
    suite_version: &str,
    family: &str,
    tier: u32,
    seed: u64,
    prompt: &str,
    answer: &str,
) -> GeneratedInstance {
    GeneratedInstance {
        suite_version: suite_version.to_string(),
        family: family.to_string(),
        tier,
        seed,
        prompt: prompt.to_string(),
        answer: answer.to_string(),
    }
}

fn signing() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[7u8; 32])
}

fn issue(now: OffsetDateTime) -> (Challenge, Ticket, GeneratedInstance) {
    let key = signing();
    let inst = instance(
        "clankdar-frontier-v1",
        "cryptarithm",
        6,
        424242,
        "solve: AB + BA = CC",
        "2454",
    );
    let opts = IssueOptions {
        family: "cryptarithm",
        tier: 6,
        ttl_seconds: Some(300),
        context: None,
        now: Some(now),
    };
    let (challenge, ticket) = issue_challenge(&opts, 424242, &inst, &key).unwrap();
    (challenge, ticket, inst)
}

#[test]
fn challenge_seals_the_seed_but_binds_it() {
    let (challenge, ticket, _) = issue(at("2026-09-18T00:00:00Z"));
    let serialized = serde_json::to_string(&challenge).unwrap();
    assert!(!serialized.contains("424242"));
    assert_eq!(challenge.seed_commit.len(), 64);
    assert_eq!(
        challenge.seed_commit,
        seed_commit(
            &challenge.suite_version,
            &challenge.family,
            challenge.tier,
            &challenge.nonce,
            ticket.seed
        )
    );
    assert_ne!(
        challenge.seed_commit,
        seed_commit(
            &challenge.suite_version,
            &challenge.family,
            challenge.tier,
            &challenge.nonce,
            999999
        )
    );
    assert_eq!(challenge.verifier.key_id.len(), 16);
    assert!(challenge.challenge_id.starts_with("att_"));
}

#[test]
fn a_correct_response_produces_a_passing_receipt_that_replays() {
    let (_, ticket, inst) = issue(at("2026-09-18T00:00:00Z"));
    let key = signing();
    let receipt = verify_response(
        &ticket,
        "2454",
        &inst,
        &key,
        Some(at("2026-09-18T00:01:00Z")),
    )
    .unwrap();
    let result = check_receipt(&receipt);
    assert!(result.ok, "check failed: {:?}", result.reason);
    assert_eq!(result.verdict, Some(true));
}

#[test]
fn a_wrong_response_produces_a_truthful_failing_receipt() {
    let (_, ticket, inst) = issue(at("2026-09-18T00:00:00Z"));
    let key = signing();
    let receipt = verify_response(
        &ticket,
        "9999",
        &inst,
        &key,
        Some(at("2026-09-18T00:01:00Z")),
    )
    .unwrap();
    let body: ReceiptBody = serde_json::from_str(&receipt.payload).unwrap();
    assert!(!body.verdict.pass);
    let result = check_receipt(&receipt);
    assert!(result.ok);
    assert_eq!(result.verdict, Some(false));
}

#[test]
fn check_rejects_tampering_at_every_layer() {
    let (_, ticket, inst) = issue(at("2026-09-18T00:00:00Z"));
    let key = signing();
    let receipt = verify_response(
        &ticket,
        "2454",
        &inst,
        &key,
        Some(at("2026-09-18T00:01:00Z")),
    )
    .unwrap();
    let mut body: serde_json::Value = serde_json::from_str(&receipt.payload).unwrap();

    let mut bad_sig = receipt.clone();
    bad_sig.signature = format!("{}AAAA", &receipt.signature[..receipt.signature.len() - 4]);
    assert!(!check_receipt(&bad_sig).ok);

    for (path, value) in [
        ("seed", serde_json::json!(424243)),
        ("response", serde_json::json!("0")),
    ] {
        let mut tampered = body.clone();
        tampered[path] = value;
        let bad = Receipt {
            payload: serde_json::to_string(&tampered).unwrap(),
            ..receipt.clone()
        };
        assert!(!check_receipt(&bad).ok, "tampered {path} must fail");
    }

    body["verdict"]["pass"] = serde_json::json!(false);
    let bad = Receipt {
        payload: serde_json::to_string(&body).unwrap(),
        ..receipt.clone()
    };
    assert!(!check_receipt(&bad).ok);

    let mut forged = body.clone();
    forged["challenge"]["prompt"] = serde_json::json!("forged");
    let bad = Receipt {
        payload: serde_json::to_string(&forged).unwrap(),
        ..receipt.clone()
    };
    assert!(!check_receipt(&bad).ok);

    let junk = Receipt {
        protocol: ATTEST_PROTOCOL.into(),
        payload: "{}".into(),
        signature: "x".into(),
    };
    assert!(!check_receipt(&junk).ok);
}

#[test]
fn a_receipt_signed_under_a_different_key_fails() {
    let (_, ticket, inst) = issue(at("2026-09-18T00:00:00Z"));
    let other = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
    let receipt = verify_response(
        &ticket,
        "2454",
        &inst,
        &other,
        Some(at("2026-09-18T00:01:00Z")),
    )
    .unwrap();
    assert!(!check_receipt(&receipt).ok);
}

#[test]
fn expired_tickets_refuse_verification_and_late_answers_fail_check() {
    let (_, ticket, inst) = issue(at("2026-09-18T00:00:00Z"));
    let key = signing();
    let expired = verify_response(&ticket, "1", &inst, &key, Some(at("2026-09-18T00:10:00Z")));
    assert_eq!(expired.unwrap_err(), AttestError::Expired);
    let late = verify_response(
        &ticket,
        "2454",
        &inst,
        &key,
        Some(at("2026-09-18T00:04:59Z")),
    )
    .unwrap();
    let mut body: serde_json::Value = serde_json::from_str(&late.payload).unwrap();
    body["verdict"]["answeredAt"] = serde_json::json!("2026-09-18T00:06:00Z");
    let bad = Receipt {
        payload: serde_json::to_string(&body).unwrap(),
        ..late
    };
    assert!(!check_receipt(&bad).ok);
}

#[test]
fn bad_options_fail_at_issue() {
    let key = signing();
    let inst = instance("clankdar-frontier-v1", "cryptarithm", 6, 1, "p", "1");
    let base = || IssueOptions {
        family: "cryptarithm",
        tier: 6,
        ttl_seconds: Some(300),
        context: None,
        now: Some(at("2026-09-18T00:00:00Z")),
    };
    assert!(issue_challenge(&base(), 1, &inst, &key).is_ok());
    assert!(issue_challenge(
        &IssueOptions {
            ttl_seconds: Some(5),
            ..base()
        },
        1,
        &inst,
        &key
    )
    .is_err());
    assert!(issue_challenge(
        &IssueOptions {
            ttl_seconds: Some(99999),
            ..base()
        },
        1,
        &inst,
        &key
    )
    .is_err());
    assert!(issue_challenge(
        &IssueOptions {
            context: Some("x".repeat(300)),
            ..base()
        },
        1,
        &inst,
        &key
    )
    .is_err());
    // Oracle output that disagrees with the request must not be signed.
    let wrong = instance("clankdar-frontier-v1", "cryptarithm", 6, 2, "p", "1");
    assert!(issue_challenge(&base(), 1, &wrong, &key).is_err());
}

#[test]
fn canonical_json_is_deterministic_and_order_insensitive() {
    let a = canonical_json(&serde_json::json!({"b": 1, "a": {"z": 2, "y": [3]}}));
    let b = canonical_json(&serde_json::json!({"a": {"y": [3], "z": 2}, "b": 1}));
    assert_eq!(a, b);
    assert_eq!(a, r#"{"a":{"y":[3],"z":2},"b":1}"#);
}

// --- scorer parity vectors (mirroring canonicalAnswer semantics) ---

#[test]
fn scorer_integer_format() {
    let f = AnswerFormat::Integer;
    assert_eq!(canonical_answer("42", f).as_deref(), Some("42"));
    assert_eq!(canonical_answer(" +042 ", f).as_deref(), Some("42"));
    assert_eq!(canonical_answer("-0", f).as_deref(), Some("0"));
    assert_eq!(canonical_answer("-007", f).as_deref(), Some("-7"));
    assert!(canonical_answer("4.2", f).is_none());
    assert!(canonical_answer("--4", f).is_none());
    assert!(canonical_answer("1e3", f).is_none());
}

#[test]
fn scorer_bits_format() {
    let f = AnswerFormat::Bits;
    assert_eq!(canonical_answer(" 0101 ", f).as_deref(), Some("0101"));
    assert!(canonical_answer("012", f).is_none());
    assert!(canonical_answer("", f).is_none());
}

#[test]
fn scorer_tokens_format() {
    let f = AnswerFormat::Tokens;
    assert_eq!(canonical_answer("a b,c", f).as_deref(), Some("A B C"));
    assert_eq!(canonical_answer("D , e", f).as_deref(), Some("D E"));
    assert!(canonical_answer("ab", f).is_none());
    assert!(canonical_answer("a 1", f).is_none());
}

#[test]
fn scorer_assignments_format() {
    let f = AnswerFormat::Assignments;
    assert_eq!(
        canonical_answer("A = knight, b=knave", f).as_deref(),
        Some("a=knight b=knave")
    );
    assert_eq!(canonical_answer("a=knave", f).as_deref(), Some("a=knave"));
    assert!(canonical_answer("a=knight a=knave", f).is_none());
    assert!(canonical_answer("a=king", f).is_none());
    assert!(canonical_answer("ab=knight", f).is_none());
}

#[test]
fn scorer_grid_format() {
    let f = AnswerFormat::Grid;
    assert_eq!(
        canonical_answer("1 2 3 / 4 5 6", f).as_deref(),
        Some(r#"[["1","2","3"],["4","5","6"]]"#)
    );
    assert_eq!(
        canonical_answer("1 2\n3 4", f).as_deref(),
        Some(r#"[["1","2"],["3","4"]]"#)
    );
    assert_eq!(
        canonical_answer("1 2 /\n3 4", f).as_deref(),
        Some(r#"[["1","2"],["3","4"]]"#)
    );
    assert!(canonical_answer("1 2 / 3", f).is_none()); // ragged
    assert!(canonical_answer("12 34", f).is_none()); // multi-digit cells
}

#[test]
fn scorer_text_format_and_rejects() {
    let f = AnswerFormat::Text;
    assert_eq!(
        canonical_answer("  hello   world ", f).as_deref(),
        Some("hello world")
    );
    assert!(canonical_answer("\u{7}", f).is_none());
    assert!(canonical_answer("  ", f).is_none());
}

#[test]
fn score_answer_matches_ts_semantics() {
    let s = score_answer("42", "42", AnswerFormat::Integer);
    assert!(s.pass && s.final_answer_match && !s.format_only);
    let s = score_answer("42", "The answer is 42", AnswerFormat::Integer);
    assert!(!s.pass && !s.final_answer_match);
    let s = score_answer("42", "answer: 42", AnswerFormat::Integer);
    assert!(!s.pass && s.final_answer_match && s.format_only);
    let s = score_answer("42", "41", AnswerFormat::Integer);
    assert!(!s.pass && !s.final_answer_match && !s.format_only);
}

// --- TypeScript interop: receipts produced by bench/attest.ts ---

#[test]
fn typescript_issued_receipts_check_offline() {
    for (fixture, verdict) in [
        ("tests/fixtures/ts_receipt_pass.json", true),
        ("tests/fixtures/ts_receipt_fail.json", false),
    ] {
        let text = std::fs::read_to_string(fixture).expect("fixture missing");
        let receipt: Receipt = serde_json::from_str(&text).expect("fixture parses");
        let result = check_receipt(&receipt);
        assert!(result.ok, "{fixture} failed: {:?}", result.reason);
        assert_eq!(result.verdict, Some(verdict));
    }
}
