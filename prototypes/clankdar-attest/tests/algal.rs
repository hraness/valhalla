//! Pinned upstream TypeScript/WASM compatibility and hardened key boundaries.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde_json::{json, Value};
use valhalla_clankdar_attest_prototype::*;

fn fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/ts_algal_compat.json")).unwrap()
}
fn oracle(version: &str, family: &str, tier: u32, seed: u64) -> Result<GeneratedInstance, String> {
    fixture()["oracleInstances"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| serde_json::from_value::<GeneratedInstance>(v.clone()).unwrap())
        .find(|v| {
            v.suite_version == version && v.family == family && v.tier == tier && v.seed == seed
        })
        .ok_or_else(|| "instance absent from independently generated fixture".into())
}
fn no_oracle(_: &str, _: &str, _: u32, _: u64) -> Result<GeneratedInstance, String> {
    panic!("invalid signature must fail before oracle execution")
}

#[test]
fn algal_actual_pinned_wasm_fixtures_replay_public_and_heldout_scores() {
    let f = fixture();
    assert_eq!(
        f["provenance"]["clankdarRevision"],
        "80fa17a41dc11efe4094279d747c408b9dc7b95e"
    );
    assert_eq!(
        f["provenance"]["algalWasmSha256"],
        "7a8a821f80388a3ba257ac46c7e3d9668e25f77323b22603974d713df1a39fff"
    );
    for (i, raw) in f["receipts"].as_array().unwrap().iter().enumerate() {
        let receipt: Receipt = serde_json::from_value(raw.clone()).unwrap();
        let result = check_receipt_with_pool(&receipt, None, oracle);
        assert!(result.ok, "{:?}", result.reason);
        assert_eq!(result.verdict, Some(i != 2));
        assert!(
            !check_receipt_with_pool(&receipt, None, |v, f, t, s| {
                let mut instance = oracle(v, f, t, s)?;
                instance.answer.push('0');
                Ok(instance)
            })
            .ok
        );
    }
    let admission: Admission = serde_json::from_value(f["admission"].clone()).unwrap();
    let result = check_admission(&admission, oracle);
    assert!(result.ok, "{:?}", result.reason);
    assert_eq!(result.verdict, Some(true));
    assert_eq!(result.passed, Some(2));
    let pool = HoldoutPool::parse(&f["holdout"]["pool"]).unwrap();
    let receipt: Receipt = serde_json::from_value(f["holdout"]["receipt"].clone()).unwrap();
    let result = check_receipt_with_pool(&receipt, Some(&pool), oracle);
    assert!(result.ok, "{:?}", result.reason);
    assert_eq!(result.verdict, Some(true));
    let undisclosed = check_receipt_with_pool(&receipt, None, no_oracle);
    assert!(undisclosed.ok);
    assert_eq!(undisclosed.replayable, Some(false));
}

#[test]
fn algal_policy_pool_and_integer_contract_match_frozen_three_cells() {
    assert_eq!(suite_version("algal"), ALGAL_SUITE_VERSION);
    assert_eq!(answer_format("algal"), AnswerFormat::Integer);
    assert_eq!(
        canonical_answer(" +00042 ", AnswerFormat::Integer).as_deref(),
        Some("42")
    );
    assert_eq!(
        canonical_answer("-0", AnswerFormat::Integer).as_deref(),
        Some("0")
    );
    assert!(!score_answer("42", "Answer: 42", answer_format("algal")).pass);
    let mut policy = json!({"suite":"algal","cells":["algal:t1","algal:t2","algal:t3"],"challenges":4,"minPass":3,"ttlSeconds":180});
    assert!(GatePolicy::parse(&policy).is_ok());
    for cell in [
        "algal:t0",
        "algal:t4",
        "arithmetic:t1",
        "h:algal:t4",
        "h:arithmetic:t1",
    ] {
        policy["cells"] = json!([cell]);
        assert!(GatePolicy::parse(&policy).is_err(), "{cell}");
    }
    let pool = HoldoutPool::parse(&fixture()["holdout"]["pool"]).unwrap();
    policy["cells"] = json!(["h:algal:t2"]);
    assert!(GatePolicy::parse_with_pool(&policy, Some(&pool)).is_ok());
    policy["cells"] = json!(["h:algal:t3"]);
    assert!(GatePolicy::parse_with_pool(&policy, Some(&pool)).is_err());
    for (family, tier) in [("algal", 0), ("algal", 4), ("arithmetic", 1)] {
        let cells = vec![HoldoutCell {
            family: family.into(),
            tier,
            label: "public-fixture-label-no-secret-0001".into(),
        }];
        let raw = json!({"protocol":HOLDOUT_PROTOCOL,"suite":"algal","poolKey":pool_key_of("algal", &cells),"cells":cells});
        assert!(HoldoutPool::parse(&raw).is_err());
    }
    for suite in ["v2", "frontier", "agent"] {
        policy["suite"] = json!(suite);
        policy["cells"] = json!(["existingoraclecell:t1"]);
        assert!(
            GatePolicy::parse(&policy).is_ok(),
            "legacy oracle membership preserved"
        );
    }
}

fn weak_material() -> (String, String) {
    let mut public = [0; 32];
    public[0] = 1; // compressed identity point
    let mut signature = [0; 64];
    signature[0] = 1; // identity R, zero s
                      // This is a concrete no-secret forgery admitted by the old loose boundary.
    let key = VerifyingKey::from_bytes(&public).unwrap();
    let sig = Signature::from_bytes(&signature);
    assert!(key.is_weak());
    assert!(key.verify(b"arbitrary fabricated transcript", &sig).is_ok());
    assert!(key
        .verify_strict(b"arbitrary fabricated transcript", &sig)
        .is_err());
    (
        URL_SAFE_NO_PAD.encode(public),
        URL_SAFE_NO_PAD.encode(signature),
    )
}

#[test]
fn algal_subject_proof_rejects_no_secret_weak_key_forgery() {
    let receipt: Receipt = serde_json::from_value(fixture()["receipts"][0].clone()).unwrap();
    let body: ReceiptBody = serde_json::from_str(&receipt.payload).unwrap();
    let (public_key, signature) = weak_material();
    assert!(!check_subject_proof(
        &body.challenge,
        &SubjectProof {
            public_key,
            signature
        }
    ));
}

#[test]
fn algal_weak_issuer_cannot_forge_receipt_admission_or_log_and_badge() {
    let (public, signature) = weak_material();
    let verifier = json!({"publicKey":public,"keyId":key_id_of(&public).unwrap()});
    let mut receipt: Receipt = serde_json::from_value(fixture()["receipts"][0].clone()).unwrap();
    let mut body: Value = serde_json::from_str(&receipt.payload).unwrap();
    body["challenge"]["verifier"] = verifier.clone();
    receipt.payload = canonical_json(&body);
    receipt.signature = signature.clone();
    let result = check_receipt_with_pool(&receipt, None, no_oracle);
    assert!(!result.ok);
    assert!(result.reason.unwrap().contains("weak Ed25519 public key"));
    let mut admission: Admission = serde_json::from_value(fixture()["admission"].clone()).unwrap();
    let mut body: Value = serde_json::from_str(&admission.payload).unwrap();
    for challenge in body["challenges"].as_array_mut().unwrap() {
        challenge["verifier"] = verifier.clone();
    }
    admission.payload = canonical_json(&body);
    admission.signature = signature.clone();
    let result = check_admission(&admission, no_oracle);
    assert!(!result.ok);
    assert_eq!(result.reason.as_deref(), Some("signature does not verify"));
    let mut log: Value = serde_json::from_str(include_str!("fixtures/ts_tlog_valid.json")).unwrap();
    log["head"]["verifier"] = verifier;
    log["head"]["signature"] = json!(signature);
    let result = check_log(&log);
    assert!(!result.ok);
    assert_eq!(
        result.reason.as_deref(),
        Some("head signature does not verify")
    );
    let badge_fixture: Value =
        serde_json::from_str(include_str!("fixtures/ts_badge_holdout.json")).unwrap();
    let mut badge = badge_fixture["badge"].clone();
    let mut body: Value = serde_json::from_str(badge["payload"].as_str().unwrap()).unwrap();
    body["subjectKey"] = json!(public);
    badge["payload"] = json!(canonical_json(&body));
    badge["signature"] = json!(signature);
    let result = check_badge(&badge, None, no_oracle);
    assert!(!result.ok);
    assert_eq!(
        result.reason.as_deref(),
        Some("subjectKey is not an Ed25519 public key")
    );
}

#[test]
fn algal_legacy_subject_proof_does_not_claim_exact_answer_or_issuer_binding() {
    let receipt: Receipt = serde_json::from_value(fixture()["receipts"][0].clone()).unwrap();
    let body: ReceiptBody = serde_json::from_str(&receipt.payload).unwrap();
    let proof: SubjectProof = serde_json::from_value(body.subject_proof.unwrap()).unwrap();
    assert!(check_subject_proof(&body.challenge, &proof));
    let mut changed = body.challenge.clone();
    changed.prompt = "different puzzle".into();
    changed.verifier.public_key = URL_SAFE_NO_PAD.encode([3; 32]);
    changed.subject = Some("different issuer claim".into());
    changed.context = Some("different room claim".into());
    // Session possession only: a separately verified issuer signature and
    // exact-artifact endorsement remain necessary for their distinct claims.
    assert!(check_subject_proof(&changed, &proof));
    changed.session_id = Some("gs_otherSession".into());
    assert!(!check_subject_proof(&changed, &proof));
}
