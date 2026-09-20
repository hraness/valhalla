//! Exact evidence, pinned scope and bounded partial-history regressions.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};
use time::{format_description::well_known::Rfc3339, Duration, OffsetDateTime};
use valhalla_clankdar_attest_prototype::*;

const NOW: &str = "2026-09-18T00:00:00Z";
const DECIDED: &str = "2026-09-18T00:01:00Z";
const OBSERVED: &str = "2026-09-18T00:02:00Z";
fn at(s: &str) -> OffsetDateTime {
    OffsetDateTime::parse(s, &Rfc3339).unwrap()
}
fn issuer() -> SigningKey {
    SigningKey::from_bytes(&[7; 32])
}
fn subject() -> SigningKey {
    SigningKey::from_bytes(&[11; 32])
}
fn public(key: &SigningKey) -> String {
    URL_SAFE_NO_PAD.encode(key.verifying_key().to_bytes())
}
fn oracle(suite: &str, family: &str, tier: u32, seed: u64) -> Result<GeneratedInstance, String> {
    Ok(GeneratedInstance {
        suite_version: suite.into(),
        family: family.into(),
        tier,
        seed,
        prompt: format!("{family} puzzle t{tier} seed {seed}"),
        answer: (seed % 1_000_000).to_string(),
    })
}
fn policy() -> GatePolicy {
    GatePolicy {
        suite: "frontier".into(),
        cells: vec!["cryptarithm:t6".into()],
        challenges: 1,
        min_pass: 1,
        ttl_seconds: 300,
    }
}
fn expectation() -> HistoryExpectation {
    HistoryExpectation {
        issuer_key: public(&issuer()),
        subject_key: public(&subject()),
        context: Some("room:test".into()),
        policy: policy(),
        max_age_seconds: 300,
        future_skew_seconds: 0,
    }
}
fn signed(body: Value) -> Admission {
    let payload = canonical_json(&body);
    Admission {
        protocol: GATE_PROTOCOL.into(),
        signature: URL_SAFE_NO_PAD.encode(issuer().sign(payload.as_bytes()).to_bytes()),
        payload,
    }
}
fn admission(id: u32, answer: Option<bool>, bound: bool) -> Admission {
    admission_cell(id, answer, bound, "cryptarithm", 6)
}
fn admission_cell(
    id: u32,
    answer: Option<bool>,
    bound: bool,
    family: &str,
    tier: u32,
) -> Admission {
    let key = subject();
    let instance = oracle(FRONTIER_SUITE_VERSION, family, tier, 123).unwrap();
    let (challenge, ticket) = issue_challenge(
        &IssueOptions {
            family,
            tier,
            ttl_seconds: Some(300),
            context: Some("room:test".into()),
            subject: Some(public(&key)),
            session_id: Some(format!("gs_{id:012}")),
            holdout_pool: None,
            now: Some(at(NOW)),
        },
        123,
        &instance,
        &issuer(),
    )
    .unwrap();
    let proof = bound.then(|| {
        subject_proof_for(
            &challenge,
            &VerifierJwk {
                kty: "OKP".into(),
                crv: "Ed25519".into(),
                x: public(&key),
                d: URL_SAFE_NO_PAD.encode(key.to_bytes()),
            },
        )
        .unwrap()
    });
    let receipts: Vec<_> = answer
        .into_iter()
        .map(|pass| {
            verify_response(
                &ticket,
                if pass { "123" } else { "124" },
                &instance,
                &issuer(),
                proof.as_ref(),
                Some(at(DECIDED)),
            )
            .unwrap()
        })
        .collect();
    signed(
        serde_json::to_value(AdmissionBody {
            kind: "admission".into(),
            session_id: format!("gs_{id:012}"),
            policy: GatePolicy {
                cells: vec![format!("{family}:t{tier}")],
                ..policy()
            },
            subject: Some(public(&key)),
            context: Some("room:test".into()),
            challenges: vec![challenge],
            receipts,
            verdict: AdmissionVerdict {
                pass: answer == Some(true),
                passed: u64::from(answer == Some(true)),
                required: 1,
                decided_at: DECIDED.into(),
            },
        })
        .unwrap(),
    )
}
fn bytes(a: &Admission) -> Vec<u8> {
    serde_json::to_vec(a).unwrap()
}
fn inspect(inputs: &[&[u8]]) -> HistorySnapshot {
    check_history(inputs, &expectation(), at(OBSERVED), None, oracle).unwrap()
}
fn badge(admissions: &[Admission]) -> Vec<u8> {
    let payload = canonical_json(
        &json!({"kind":"badge", "subjectKey":public(&subject()), "admissions": admissions,"issuedAt":OBSERVED}),
    );
    serde_json::to_vec(&json!({"protocol":BADGE_PROTOCOL,"signature":URL_SAFE_NO_PAD.encode(subject().sign(payload.as_bytes()).to_bytes()),"payload":payload})).unwrap()
}

#[test]
fn pass_fail_and_zero_answer_claim_stay_separate() {
    let files = [
        bytes(&admission(1, Some(true), true)),
        bytes(&admission(2, Some(false), true)),
        bytes(&admission(3, None, false)),
    ];
    let view = inspect(&files.iter().map(Vec::as_slice).collect::<Vec<_>>());
    assert!(view.rejected().is_empty(), "{:?}", view.rejected());
    assert_eq!(view.records().len(), 3);
    assert_eq!(view.coverage(), HistoryCoverage::PartialShared);
    assert_eq!(view.subject_bound_outcomes(), (1, 1));
    let unanswered = view
        .records()
        .iter()
        .find(|r| r.session_id().ends_with('3'))
        .unwrap();
    assert_eq!(unanswered.binding(), HistoryBinding::IssuerClaimed);
    assert_eq!(unanswered.outcome(), HistoryOutcome::Fail);
    assert_eq!(
        unanswered.challenges()[0].outcome(),
        HistoryChallengeOutcome::Unanswered
    );
    assert_eq!(
        unanswered.challenges()[0].replay(),
        HistoryChallengeReplay::NoResponse
    );
    assert_eq!(
        serde_json::to_value(unanswered).unwrap()["answered_receipts"],
        0
    );
    assert_eq!(view.observed_at(), OBSERVED);
}
#[test]
fn outer_whitespace_deduplicates_and_badge_upgrades_only_exact_evidence() {
    let a = admission(1, Some(true), true);
    let raw = bytes(&a);
    let pretty = serde_json::to_vec_pretty(&a).unwrap();
    let endorsed = badge(&[a]);
    let view = inspect(&[&raw, &pretty, &endorsed]);
    assert!(view.rejected().is_empty(), "{:?}", view.rejected());
    assert_eq!(view.records().len(), 1);
    assert_eq!(view.duplicate_count(), 2);
    assert_eq!(view.records()[0].source_hashes().len(), 3);
    assert_eq!(view.records()[0].binding(), HistoryBinding::BadgeEndorsed);
    assert_eq!(view.subject_bound_outcomes(), (1, 0));
}
#[test]
fn competing_verified_same_session_is_not_another_solve() {
    let pass = bytes(&admission(7, Some(true), true));
    let fail = bytes(&admission(7, Some(false), true));
    let view = inspect(&[&pass, &fail]);
    assert!(view.rejected().is_empty(), "{:?}", view.rejected());
    assert_eq!(view.records().len(), 2);
    assert_eq!(view.conflicts(), 1);
    assert!(view.records().iter().all(HistoryRecord::conflicted));
    assert_eq!(view.subject_bound_outcomes(), (0, 0));
    let reversed = inspect(&[&fail, &pass]);
    assert_eq!(
        view.records()
            .iter()
            .map(HistoryRecord::signed_evidence_hash)
            .collect::<Vec<_>>(),
        reversed
            .records()
            .iter()
            .map(HistoryRecord::signed_evidence_hash)
            .collect::<Vec<_>>()
    );
}
#[test]
fn full_key_exact_context_policy_and_invalid_signature_fail_closed() {
    let original = bytes(&admission(1, Some(true), true));
    let mut pins = Vec::new();
    let mut p = expectation();
    p.issuer_key = public(&SigningKey::from_bytes(&[9; 32]));
    pins.push(p);
    let mut p = expectation();
    p.subject_key = public(&SigningKey::from_bytes(&[9; 32]));
    pins.push(p);
    let mut p = expectation();
    p.context = None;
    pins.push(p);
    let mut p = expectation();
    p.context = Some("room:other".into());
    pins.push(p);
    let mut p = expectation();
    p.policy.ttl_seconds = 301;
    pins.push(p);
    for expected in pins {
        let view = check_history(&[&original], &expected, at(OBSERVED), None, oracle).unwrap();
        assert!(view.records().is_empty());
        assert_eq!(view.rejected().len(), 1);
        assert_eq!(view.subject_bound_outcomes(), (0, 0));
    }
    let mut bad = admission(2, Some(true), true);
    bad.signature = URL_SAFE_NO_PAD.encode([0; 64]);
    let view = inspect(&[&original, &bytes(&bad)]);
    assert_eq!(view.records().len(), 1);
    assert_eq!(view.rejected().len(), 1);
    assert_eq!(view.conflicts(), 0);
}
#[test]
fn stale_is_visible_and_future_or_out_of_window_is_rejected() {
    let file = bytes(&admission(1, Some(true), true));
    let mut expected = expectation();
    expected.max_age_seconds = 60;
    let boundary = check_history(&[&file], &expected, at(OBSERVED), None, oracle).unwrap();
    assert!(boundary.records()[0].recent());
    let stale = check_history(
        &[&file],
        &expected,
        at(OBSERVED) + Duration::seconds(1),
        None,
        oracle,
    )
    .unwrap();
    assert_eq!(stale.records().len(), 1);
    assert!(!stale.records()[0].recent());
    assert_eq!(stale.subject_bound_outcomes(), (0, 0));
    let future = check_history(&[&file], &expected, at(NOW), None, oracle).unwrap();
    assert_eq!(future.rejected().len(), 1);
    expected.future_skew_seconds = 60;
    assert_eq!(
        check_history(&[&file], &expected, at(NOW), None, oracle)
            .unwrap()
            .records()
            .len(),
        1
    );
    let zero = admission(2, None, false);
    for stamp in ["invalid", "2026-09-18T00:06:00Z", "2026-09-17T23:59:59Z"] {
        let mut body: Value = serde_json::from_str(&zero.payload).unwrap();
        body["verdict"]["decidedAt"] = json!(stamp);
        assert_eq!(inspect(&[&bytes(&signed(body))]).rejected().len(), 1);
    }
}
#[test]
fn zero_answer_does_not_hide_invalid_expiry() {
    let mut body: Value = serde_json::from_str(&admission(1, None, false).payload).unwrap();
    body["challenges"][0]["expiresAt"] = json!("not-a-time");
    let view = inspect(&[&bytes(&signed(body))]);
    assert!(view.records().is_empty());
    assert_eq!(view.rejected().len(), 1);
}
#[test]
fn changed_or_missing_oracle_never_becomes_shallow_success() {
    let file = bytes(&admission(1, Some(true), true));
    let view = check_history(
        &[&file],
        &expectation(),
        at(OBSERVED),
        None,
        |_, _, _, _| Err("evaluator unavailable".into()),
    )
    .unwrap();
    assert!(view.records().is_empty());
    assert_eq!(view.rejected().len(), 1);
    let view = check_history(
        &[&file],
        &expectation(),
        at(OBSERVED),
        None,
        |s, f, t, n| {
            let mut i = oracle(s, f, t, n)?;
            i.prompt.push('!');
            Ok(i)
        },
    )
    .unwrap();
    assert!(view.records().is_empty());
    assert_eq!(view.rejected().len(), 1);
}
#[test]
fn pages_are_bounded_and_cursors_bind_clock_and_exact_inputs() {
    let files: Vec<_> = (0..17).map(|i| bytes(&admission(i, None, false))).collect();
    let refs: Vec<_> = files.iter().map(Vec::as_slice).collect();
    let view = inspect(&refs);
    assert!(view.rejected().is_empty());
    let page = view.page(None, 16).unwrap();
    assert_eq!(page.records().len(), 16);
    assert_eq!(page.next_offset(), Some(16));
    let cursor = HistoryCursor::decode(&page.next().unwrap().encode()).unwrap();
    assert_eq!(view.page(Some(&cursor), 16).unwrap().records().len(), 1);
    assert!(view.page_offset(18, 16).is_err());
    assert!(view.page(None, 17).is_err());
    assert!(view.page(None, 0).is_err());
    let changed = check_history(
        &refs,
        &expectation(),
        at(OBSERVED) + Duration::seconds(1),
        None,
        oracle,
    )
    .unwrap();
    assert!(changed.page(Some(&cursor), 16).is_err());
    assert!(HistoryCursor::decode(&format!("{}:01", view.snapshot_hash())).is_err());
}
#[test]
fn aggregate_bounds_apply_before_any_replay() {
    let file = bytes(&admission(1, Some(true), true));
    let never = |_: &str, _: &str, _: u32, _: u64| -> Result<GeneratedInstance, String> {
        panic!("bounds must precede replay")
    };
    assert_eq!(
        check_history(
            &vec![file.as_slice(); 65],
            &expectation(),
            at(OBSERVED),
            None,
            never
        )
        .unwrap_err(),
        HistoryError::Bounds
    );
    assert_eq!(
        check_history(
            &[&vec![b' '; MAX_HISTORY_BYTES + 1]],
            &expectation(),
            at(OBSERVED),
            None,
            never
        )
        .unwrap_err(),
        HistoryError::Bounds
    );
    let mut a: Value = serde_json::from_slice(&file).unwrap();
    let mut body: Value = serde_json::from_str(a["payload"].as_str().unwrap()).unwrap();
    body["receipts"] = json!(vec![body["receipts"][0].clone(); 17]);
    a["payload"] = json!(canonical_json(&body));
    assert_eq!(
        check_history(
            &[&file, &serde_json::to_vec(&a).unwrap()],
            &expectation(),
            at(OBSERVED),
            None,
            never
        )
        .unwrap_err(),
        HistoryError::Bounds
    );
}
#[test]
fn malformed_inputs_and_weak_expectations_are_not_failed_attempts() {
    let view = inspect(&[b"not json", b"{\"protocol\":\"unknown\"}"]);
    assert!(view.records().is_empty());
    assert_eq!(view.rejected().len(), 2);
    let mut expected = expectation();
    let mut identity = [0; 32];
    identity[0] = 1;
    expected.issuer_key = URL_SAFE_NO_PAD.encode(identity);
    assert!(matches!(
        check_history(&[], &expected, at(OBSERVED), None, oracle),
        Err(HistoryError::Expectations(_))
    ));
}
#[test]
fn heldout_issuer_score_and_disclosed_replay_are_explicit() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/ts_badge_holdout.json")).unwrap();
    let badge = &fixture["badge"];
    let body: Value = serde_json::from_str(badge["payload"].as_str().unwrap()).unwrap();
    let admission: Value =
        serde_json::from_str(body["admissions"][0]["payload"].as_str().unwrap()).unwrap();
    let expected = HistoryExpectation {
        issuer_key: admission["challenges"][0]["verifier"]["publicKey"]
            .as_str()
            .unwrap()
            .into(),
        subject_key: body["subjectKey"].as_str().unwrap().into(),
        context: None,
        policy: GatePolicy::parse(&admission["policy"]).unwrap(),
        max_age_seconds: 300,
        future_skew_seconds: 0,
    };
    let raw = serde_json::to_vec(badge).unwrap();
    let instances: Vec<GeneratedInstance> =
        serde_json::from_value(fixture["instances"].clone()).unwrap();
    let replay = |s: &str, f: &str, t: u32, n: u64| {
        instances
            .iter()
            .find(|i| i.suite_version == s && i.family == f && i.tier == t && i.seed == n)
            .cloned()
            .ok_or("missing fixture instance".to_string())
    };
    let unreplayed = check_history(&[&raw], &expected, at(OBSERVED), None, replay).unwrap();
    assert!(
        unreplayed.rejected().is_empty(),
        "{:?}",
        unreplayed.rejected()
    );
    assert_eq!(
        unreplayed.records()[0].replay(),
        HistoryReplay::HeldoutUnreplayed { receipts: 2 }
    );
    assert_eq!(unreplayed.subject_bound_outcomes(), (0, 0));
    assert!(unreplayed.records()[0]
        .challenges()
        .iter()
        .all(|challenge| challenge.replay() == HistoryChallengeReplay::HeldoutUnreplayed));
    assert_eq!(unreplayed.records()[0].challenges()[0].family(), "sat");
    assert_eq!(unreplayed.records()[0].challenges()[0].tier(), 4);
    let pools = [HoldoutPool::parse(&fixture["pool"]).unwrap()];
    let replayed = check_history(&[&raw], &expected, at(OBSERVED), Some(&pools), replay).unwrap();
    assert!(replayed.rejected().is_empty(), "{:?}", replayed.rejected());
    assert_eq!(
        replayed.records()[0].replay(),
        HistoryReplay::IndependentlyReplayed
    );
    assert_eq!(replayed.subject_bound_outcomes(), (1, 0));
    assert!(replayed.records()[0]
        .challenges()
        .iter()
        .all(|challenge| challenge.replay() == HistoryChallengeReplay::IndependentlyReplayed));
}

#[test]
fn authenticated_cross_scope_equivocation_excludes_pinned_row() {
    let accepted = bytes(&admission(1, Some(true), true));
    let mut body: Value = serde_json::from_str(&admission(1, None, false).payload).unwrap();
    body["context"] = json!("another:scope");
    body["challenges"][0]["context"] = json!("another:scope");
    let competing = bytes(&signed(body));
    let view = inspect(&[&accepted, &competing]);
    assert_eq!(view.records().len(), 1);
    assert_eq!(view.rejected().len(), 1);
    assert_eq!(view.conflicts(), 1);
    assert!(view.records()[0].conflicted());
    assert_eq!(view.subject_bound_outcomes(), (0, 0));
}

#[test]
fn per_challenge_summary_matches_ids_across_mixed_reordered_receipts() {
    let pass = admission_cell(33, Some(true), true, "cryptarithm", 6);
    let fail = admission_cell(33, Some(false), true, "registervm", 5);
    let missing = admission_cell(33, None, false, "cryptarithm", 6);
    let bodies: Vec<Value> = [pass, fail, missing]
        .iter()
        .map(|a| serde_json::from_str(&a.payload).unwrap())
        .collect();
    let mut combined = bodies[0].clone();
    combined["challenges"] = json!([
        bodies[0]["challenges"][0],
        bodies[1]["challenges"][0],
        bodies[2]["challenges"][0]
    ]);
    // Reverse receipt order deliberately: summaries must use checked IDs.
    combined["receipts"] = json!([bodies[1]["receipts"][0], bodies[0]["receipts"][0]]);
    let mixed_policy = GatePolicy {
        cells: vec!["cryptarithm:t6".into(), "registervm:t5".into()],
        challenges: 3,
        min_pass: 2,
        ..policy()
    };
    combined["policy"] = serde_json::to_value(&mixed_policy).unwrap();
    combined["verdict"]["pass"] = json!(false);
    combined["verdict"]["passed"] = json!(1);
    combined["verdict"]["required"] = json!(2);
    let mut expected = expectation();
    expected.policy = mixed_policy;
    let view = check_history(
        &[&bytes(&signed(combined))],
        &expected,
        at(OBSERVED),
        None,
        oracle,
    )
    .unwrap();
    assert!(view.rejected().is_empty(), "{:?}", view.rejected());
    let row = &view.records()[0];
    assert_eq!(row.outcome(), HistoryOutcome::Fail);
    assert_eq!(row.challenges().len(), 3);
    for (i, (family, tier, outcome, replay)) in [
        (
            "cryptarithm",
            6,
            HistoryChallengeOutcome::Pass,
            HistoryChallengeReplay::IndependentlyReplayed,
        ),
        (
            "registervm",
            5,
            HistoryChallengeOutcome::Fail,
            HistoryChallengeReplay::IndependentlyReplayed,
        ),
        (
            "cryptarithm",
            6,
            HistoryChallengeOutcome::Unanswered,
            HistoryChallengeReplay::NoResponse,
        ),
    ]
    .iter()
    .enumerate()
    {
        let challenge = &row.challenges()[i];
        assert_eq!(
            challenge.challenge_id(),
            bodies[i]["challenges"][0]["challengeId"].as_str().unwrap()
        );
        assert_eq!(challenge.suite_version(), FRONTIER_SUITE_VERSION);
        assert_eq!(challenge.family(), *family);
        assert_eq!(challenge.tier(), *tier);
        assert_eq!(challenge.outcome(), *outcome);
        assert_eq!(challenge.replay(), *replay);
        let value = serde_json::to_value(challenge).unwrap();
        assert_eq!(
            value
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            vec![
                "challenge_id",
                "family",
                "outcome",
                "replay",
                "suite_version",
                "tier"
            ]
        );
    }
}
