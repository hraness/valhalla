//! Transparency-log (clankdar-tlog-v1) checking tests.
//!
//! Fixture logs under `tests/fixtures/ts_tlog_*.json` are real
//! TypeScript-built logs (`bench/tlog.ts` over a `GateStore` ledger);
//! tampered fixtures carry a re-signed head where needed so each exercises
//! exactly one check. Fabricated logs are built in Rust through
//! `entries_for` plus a local `sign_head` mirror.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use valhalla_clankdar_attest_prototype::*;

const NOW: &str = "2026-09-18T00:00:00Z";
const LATER: &str = "2026-09-18T00:01:00Z";

fn at(iso: &str) -> OffsetDateTime {
    OffsetDateTime::parse(iso, &Rfc3339).unwrap()
}

fn derive_bytes(label: &str) -> [u8; 32] {
    Sha256::digest(label.as_bytes()).into()
}

/// The issuer key — derived, never embedded key material.
fn signing() -> SigningKey {
    SigningKey::from_bytes(&derive_bytes("clankdar-tlog test issuer key"))
}

/// A second issuer key for the foreign-head cases.
fn other_signing() -> SigningKey {
    SigningKey::from_bytes(&derive_bytes("clankdar-tlog test foreign key"))
}

/// The fabricated generator seed — derived from a label, not a literal.
fn seed() -> u64 {
    u32::from_be_bytes(
        derive_bytes("clankdar-tlog test seed")[..4]
            .try_into()
            .unwrap(),
    ) as u64
}

/// A gate-session-shaped id derived from its tag (`gs_` + 12 id chars).
fn session_id(tag: u64) -> String {
    format!("gs_{tag:012}")
}

fn public_key(key: &SigningKey) -> String {
    URL_SAFE_NO_PAD.encode(key.verifying_key().to_bytes())
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// `signHead` from bench/tlog.ts: Ed25519 over `canonical()` of the head
/// minus `signature`.
fn sign_head(count: u64, head: &str, key: &SigningKey) -> Value {
    let public = public_key(key);
    let mut body = json!({
        "protocol": TLOG_PROTOCOL,
        "kind": "head",
        "count": count,
        "head": head,
        "issuedAt": NOW,
        "verifier": {"keyId": key_id_of(&public).unwrap(), "publicKey": public},
    });
    let signature = URL_SAFE_NO_PAD.encode(key.sign(canonical_json(&body).as_bytes()).to_bytes());
    body.as_object_mut()
        .unwrap()
        .insert("signature".to_string(), json!(signature));
    body
}

/// A fabricated `{type:"session", session}` ledger record — the digest
/// input is verbatim JSON, so a minimal record is honest here.
fn session_record(id: &str) -> Value {
    json!({
        "type": "session",
        "session": {"protocol": GATE_PROTOCOL, "kind": "session", "sessionId": id},
    })
}

/// A fabricated `{type:"decision", sessionId, admission, receipts}` record.
fn decision_record(id: &str) -> Value {
    json!({
        "type": "decision",
        "sessionId": id,
        "admission": {"protocol": GATE_PROTOCOL},
        "receipts": [],
    })
}

/// Build `{head, entries}` over fabricated records, head signed by `key`.
fn log_over(records: &[Value], key: &SigningKey) -> Value {
    let entries = entries_for(records);
    let last = entries
        .last()
        .map(|e| e.entry_hash.clone())
        .unwrap_or_else(|| "0".repeat(64));
    json!({
        "head": sign_head(entries.len() as u64, &last, key),
        "entries": serde_json::to_value(&entries).unwrap(),
    })
}

fn reason(check: &LogCheck) -> &str {
    check.reason.as_deref().unwrap_or("")
}

fn fixture(path: &str) -> Value {
    let text = std::fs::read_to_string(format!("tests/fixtures/{path}"))
        .unwrap_or_else(|_| panic!("{path} missing"));
    serde_json::from_str(&text).unwrap_or_else(|_| panic!("{path} parses"))
}

// --- fabricated admissions (same machinery as the gate tests) --------------

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

struct Session {
    policy: GatePolicy,
    challenges: Vec<Challenge>,
    tickets: Vec<Ticket>,
    instances: Vec<GeneratedInstance>,
}

/// A one-challenge session minted entirely in Rust — no generator oracle
/// needed to construct it.
fn issue_session(session_id: &str) -> Session {
    let key = signing();
    let policy = GatePolicy {
        suite: "frontier".to_string(),
        cells: vec!["cryptarithm:t6".to_string()],
        challenges: 1,
        min_pass: 1,
        ttl_seconds: 300,
    };
    let seed = seed();
    // The answer is derived from the seed — the checker never sees a
    // magic literal.
    let inst = instance(
        "cryptarithm",
        6,
        seed,
        "a fabricated puzzle",
        &format!("{}", seed % 10_000),
    );
    let opts = IssueOptions {
        family: "cryptarithm",
        tier: 6,
        ttl_seconds: Some(300),
        context: None,
        subject: None,
        session_id: Some(session_id.to_string()),
        now: Some(at(NOW)),
    };
    let (challenge, ticket) = issue_challenge(&opts, seed, &inst, &key).unwrap();
    Session {
        policy,
        challenges: vec![challenge],
        tickets: vec![ticket],
        instances: vec![inst],
    }
}

/// Consume the session like `submitSession`: one canonical response mints
/// a receipt, then the admission body is signed by the session key.
fn decide(session: &Session) -> Admission {
    let key = signing();
    let response = session.tickets[0].expected.clone();
    let receipt = verify_response(
        &session.tickets[0],
        &response,
        &session.instances[0],
        &key,
        None,
        Some(at(LATER)),
    )
    .unwrap();
    let body = json!({
        "kind": "admission",
        "sessionId": session.challenges[0].session_id,
        "policy": serde_json::to_value(&session.policy).unwrap(),
        "challenges": serde_json::to_value(&session.challenges).unwrap(),
        "receipts": [serde_json::to_value(&receipt).unwrap()],
        "verdict": {"pass": true, "passed": 1, "required": 1, "decidedAt": LATER},
    });
    let payload = canonical_json(&body);
    Admission {
        protocol: GATE_PROTOCOL.to_string(),
        signature: URL_SAFE_NO_PAD.encode(key.sign(payload.as_bytes()).to_bytes()),
        payload,
    }
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

// --- entries_for / entry_hash ----------------------------------------------

#[test]
fn entries_chain_digests_and_prevs_like_the_ts_builder() {
    let records = [
        session_record(&session_id(1)),
        decision_record(&session_id(1)),
        session_record(&session_id(2)),
    ];
    let entries = entries_for(&records);
    assert_eq!(entries.len(), 3);
    // digest = SHA-256 over `canonical()` of the verbatim ledger record.
    for (entry, record) in entries.iter().zip(records.iter()) {
        assert_eq!(entry.digest, sha256_hex(canonical_json(record).as_bytes()));
        assert_eq!(entry_hash(&entry.body()), entry.entry_hash);
    }
    // Genesis prev, then each `prev` chains the previous `entryHash`.
    assert_eq!(entries[0].prev, "0".repeat(64));
    assert_eq!(entries[1].prev, entries[0].entry_hash);
    assert_eq!(entries[2].prev, entries[1].entry_hash);
    // `entryHash` covers exactly the five body fields.
    let body = json!({
        "index": 1, "type": "decision", "sessionId": session_id(1),
        "digest": entries[1].digest, "prev": entries[1].prev,
    });
    assert_eq!(
        entries[1].entry_hash,
        sha256_hex(canonical_json(&body).as_bytes())
    );
    // The session entry reads its id off `session.sessionId`; the decision
    // off `sessionId` — mirroring the TypeScript ternary.
    assert_eq!(entries[0].session_id, session_id(1));
    assert_eq!(entries[1].session_id, session_id(1));
}

#[test]
fn typed_serde_round_trips_and_tolerates_unknown_members() {
    let entries = entries_for(&[session_record(&session_id(1))]);
    let value = serde_json::to_value(&entries[0]).unwrap();
    let mut extended = value.clone();
    extended["futureMember"] = json!({"nested": true});
    // Unknown members are tolerated (no deny_unknown_fields) — the
    // protocol permits them in future versions.
    let parsed: TlogHashedEntry = serde_json::from_value(extended).unwrap();
    assert_eq!(parsed.entry_hash, entries[0].entry_hash);
    // A float index deserializes like the JS number it is (`4.0` is `4`).
    let mut float_index = value;
    float_index["index"] = json!(0.0);
    let parsed: TlogHashedEntry = serde_json::from_value(float_index).unwrap();
    assert_eq!(parsed.index, 0);
}

// --- check_log: envelope and entry shape -----------------------------------

#[test]
fn a_valid_fabricated_log_checks() {
    let key = signing();
    let log = log_over(
        &[
            session_record(&session_id(1)),
            decision_record(&session_id(1)),
            session_record(&session_id(2)),
        ],
        &key,
    );
    let check = check_log(&log);
    assert!(check.ok, "{:?}", check.reason);
    assert_eq!(check.count, Some(3));
    // The typed view parses too, and every recorded hash recomputes.
    let typed: TransparencyLog = serde_json::from_value(log).unwrap();
    assert_eq!(typed.head.count, 3);
    for entry in &typed.entries {
        assert_eq!(entry_hash(&entry.body()), entry.entry_hash);
    }
}

#[test]
fn an_empty_log_checks_at_genesis() {
    let log = log_over(&[], &signing());
    let check = check_log(&log);
    assert!(check.ok, "{:?}", check.reason);
    assert_eq!(check.count, Some(0));
    assert_eq!(log["head"]["head"], json!("0".repeat(64)));
}

#[test]
fn non_object_logs_and_non_array_entries_fail() {
    for log in [json!(null), json!("tlog"), json!([{"head": {}}])] {
        assert_eq!(reason(&check_log(&log)), "not a transparency log");
    }
    for entries in [json!("nope"), json!({"0": {}}), json!(5)] {
        let log = json!({"entries": entries, "head": null});
        assert_eq!(reason(&check_log(&log)), "entries is not an array");
    }
}

#[test]
fn entry_shape_is_checked_before_the_chain() {
    let entry = serde_json::to_value(&entries_for(&[session_record(&session_id(1))])[0]).unwrap();
    let wrap = |entry: Value| json!({"entries": [entry], "head": null});
    // A scalar entry is malformed; a JS array *is* an object, so it falls
    // through to the index check like the TypeScript `!==` chain.
    assert_eq!(
        reason(&check_log(&wrap(json!("x")))),
        "entry 0 is malformed"
    );
    assert_eq!(
        reason(&check_log(&wrap(json!([0])))),
        "entry 0 has the wrong index"
    );
    for (member, value, expected) in [
        ("index", json!(5), "entry 0 has the wrong index"),
        ("index", json!("0"), "entry 0 has the wrong index"),
        ("type", json!("receipt"), "entry 0 has an unknown type"),
        ("sessionId", json!(""), "entry 0 has no sessionId"),
        ("sessionId", json!(null), "entry 0 has no sessionId"),
        ("digest", json!("zz"), "entry 0 has a malformed digest"),
        (
            "digest",
            json!("A".repeat(64)),
            "entry 0 has a malformed digest",
        ),
        ("prev", json!("zz"), "entry 0 has a malformed prev"),
        (
            "entryHash",
            json!("zz"),
            "entry 0 has a malformed entryHash",
        ),
    ] {
        let mut tampered = entry.clone();
        tampered[member] = value.clone();
        let check = check_log(&wrap(tampered));
        assert_eq!(reason(&check), expected, "{member}={value:?}");
    }
    // A missing member fails its own check, not a parse.
    for (member, expected) in [
        ("index", "entry 0 has the wrong index"),
        ("type", "entry 0 has an unknown type"),
        ("sessionId", "entry 0 has no sessionId"),
        ("digest", "entry 0 has a malformed digest"),
    ] {
        let mut tampered = entry.clone();
        tampered.as_object_mut().unwrap().remove(member);
        assert_eq!(
            reason(&check_log(&wrap(tampered))),
            expected,
            "missing {member}"
        );
    }
    // The head is never reached when an entry fails — `null` proves it.
}

#[test]
fn ledger_semantics_are_checked_on_entry_order() {
    let key = signing();
    let s1 = session_id(1);
    let s2 = session_id(2);
    // A session is issued once.
    let log = log_over(&[session_record(&s1), session_record(&s1)], &key);
    assert_eq!(reason(&check_log(&log)), "entry 1 re-issues a session");
    // A decision names an issued, still-open session — strictly earlier:
    // the session entry at a later index does not rescue it.
    let log = log_over(&[decision_record(&s1), session_record(&s1)], &key);
    assert_eq!(
        reason(&check_log(&log)),
        "entry 0 decides an unknown or decided session"
    );
    let log = log_over(&[session_record(&s1), decision_record(&s2)], &key);
    assert_eq!(
        reason(&check_log(&log)),
        "entry 1 decides an unknown or decided session"
    );
    let log = log_over(
        &[
            session_record(&s1),
            decision_record(&s1),
            decision_record(&s1),
        ],
        &key,
    );
    assert_eq!(
        reason(&check_log(&log)),
        "entry 2 decides an unknown or decided session"
    );
}

#[test]
fn the_chain_and_hashes_are_recomputed() {
    let key = signing();
    let records = [
        session_record(&session_id(1)),
        decision_record(&session_id(1)),
        session_record(&session_id(2)),
    ];
    let entries = entries_for(&records);
    // `prev` pointing anywhere but the real previous hash breaks the chain.
    let mut tampered = entries.clone();
    tampered[1].prev = tampered[0].prev.clone(); // genesis again
    let log = json!({
        "head": sign_head(3, &tampered[2].entry_hash, &key),
        "entries": serde_json::to_value(&tampered).unwrap(),
    });
    assert_eq!(reason(&check_log(&log)), "entry 1 breaks the chain");
    // A well-shaped `entryHash` that does not cover the body fails.
    let mut tampered = entries.clone();
    tampered[1].entry_hash = tampered[0].entry_hash.clone();
    let log = json!({
        "head": sign_head(3, &tampered[2].entry_hash, &key),
        "entries": serde_json::to_value(&tampered).unwrap(),
    });
    assert_eq!(reason(&check_log(&log)), "entry 1 hash does not recompute");
}

#[test]
fn head_shape_and_signature_are_checked_last() {
    let key = signing();
    let log = log_over(&[session_record(&session_id(1))], &key);
    // Head presence: null/scalars are missing; an array is a JS object and
    // falls through to the protocol check.
    let mut missing = log.clone();
    missing["head"] = json!(null);
    assert_eq!(reason(&check_log(&missing)), "head is missing");
    let mut array = log.clone();
    array["head"] = json!([]);
    assert_eq!(reason(&check_log(&array)), "head is not a tlog head");
    for (member, value) in [
        ("protocol", json!(ATTEST_PROTOCOL)),
        ("protocol", json!(null)),
        ("kind", json!("tree")),
    ] {
        let mut tampered = log.clone();
        tampered["head"][member] = value;
        assert_eq!(reason(&check_log(&tampered)), "head is not a tlog head");
    }
    let mut tampered = log.clone();
    tampered["head"]["count"] = json!(2);
    assert_eq!(
        reason(&check_log(&tampered)),
        "head count does not match entries"
    );
    let mut tampered = log.clone();
    tampered["head"]["count"] = json!("1");
    assert_eq!(
        reason(&check_log(&tampered)),
        "head count does not match entries"
    );
    let mut tampered = log.clone();
    tampered["head"]["head"] = json!("f".repeat(64));
    assert_eq!(
        reason(&check_log(&tampered)),
        "head does not match the last entry"
    );
    let mut tampered = log.clone();
    tampered["head"]["issuedAt"] = json!("not a timestamp");
    assert_eq!(reason(&check_log(&tampered)), "head issuedAt is malformed");
    let mut tampered = log.clone();
    tampered["head"]["verifier"]["keyId"] = json!("f".repeat(16));
    assert_eq!(
        reason(&check_log(&tampered)),
        "verifier keyId does not match the public key"
    );
    let mut tampered = log.clone();
    let sig = tampered["head"]["signature"].as_str().unwrap().to_string();
    tampered["head"]["signature"] = json!(format!("{}AAAA", &sig[..sig.len() - 4]));
    assert_eq!(
        reason(&check_log(&tampered)),
        "head signature does not verify"
    );
    // A head signed by a different key still verifies — the log binds the
    // issuer's history under *its own* key, whoever that key is.
    let other = log_over(&[session_record(&session_id(1))], &other_signing());
    let check = check_log(&other);
    assert!(check.ok, "{:?}", check.reason);
}

// --- prove_session ---------------------------------------------------------

#[test]
fn prove_reports_indexes_under_the_signed_head() {
    let key = signing();
    let (s1, s2) = (session_id(1), session_id(2));
    let log = log_over(
        &[
            session_record(&s1),
            decision_record(&s1),
            session_record(&s2),
        ],
        &key,
    );
    let decided = prove_session(&log, &s1).unwrap();
    assert_eq!(decided.session_id, s1);
    assert_eq!(decided.session_index, 0);
    assert_eq!(decided.decision_index, Some(1));
    // The echoed head is the signed head — protocol, count, and issuer key.
    assert_eq!(decided.head.protocol, TLOG_PROTOCOL);
    assert_eq!(decided.head.count, 3);
    assert_eq!(
        decided.head.verifier.key_id,
        key_id_of(&public_key(&key)).unwrap()
    );
    let undecided = prove_session(&log, &s2).unwrap();
    assert_eq!(undecided.session_index, 2);
    // `decisionIndex: null` while undecided, matching the TS proof shape.
    assert_eq!(undecided.decision_index, None);
    assert!(serde_json::to_value(&undecided).unwrap()["decisionIndex"].is_null());
}

#[test]
fn prove_requires_a_checked_log_and_a_logged_session() {
    let key = signing();
    let s1 = session_id(1);
    let mut log = log_over(&[session_record(&s1)], &key);
    log["entries"][0]["digest"] = json!("zz");
    let error = prove_session(&log, &s1).unwrap_err();
    assert_eq!(
        error.to_string(),
        "transparency log failed check: entry 0 has a malformed digest"
    );
    let log = log_over(&[session_record(&s1)], &key);
    let error = prove_session(&log, &session_id(9)).unwrap_err();
    assert_eq!(
        error.to_string(),
        format!("session {} is not in the log", session_id(9))
    );
}

// --- check_logged_admission --------------------------------------------------

#[test]
fn a_logged_decided_admission_admits() {
    let key = signing();
    let s1 = session_id(1);
    let session = issue_session(&s1);
    let admission = decide(&session);
    let log = log_over(&[session_record(&s1), decision_record(&s1)], &key);
    let check = check_logged_admission(&log, &admission, oracle(session.instances.clone()));
    assert_eq!(
        check,
        AdmittedCheck {
            ok: true,
            verdict: Some(true),
            passed: Some(1),
            reason: None,
        }
    );
}

#[test]
fn unlogged_and_undecided_sessions_reject() {
    let key = signing();
    let (s1, s2) = (session_id(1), session_id(2));
    let session2 = issue_session(&s2);
    let admission = decide(&session2);
    // A valid admission whose sessionId never reached the log.
    let log = log_over(&[session_record(&s1), decision_record(&s1)], &key);
    let check = check_logged_admission(&log, &admission, oracle(session2.instances.clone()));
    assert_eq!(
        check.reason,
        Some(format!("session {s2} is not in the transparency log"))
    );
    // verdict/passed still report the admission's own replay.
    assert_eq!(check.verdict, Some(true));
    assert_eq!(check.passed, Some(1));
    // A logged session with no logged decision is not yet admissible.
    let s3 = session_id(3);
    let session3 = issue_session(&s3);
    let admission3 = decide(&session3);
    let log = log_over(&[session_record(&s3)], &key);
    let check = check_logged_admission(&log, &admission3, oracle(session3.instances.clone()));
    assert_eq!(
        check.reason,
        Some(format!("session {s3} has no logged decision"))
    );
    assert_eq!(check.verdict, Some(true));
}

#[test]
fn a_bad_admission_or_a_bad_log_fails_first() {
    let key = signing();
    let s1 = session_id(1);
    let session = issue_session(&s1);
    let admission = decide(&session);
    let log = log_over(&[session_record(&s1), decision_record(&s1)], &key);
    // The admission check runs first — its reason propagates verbatim.
    let mut bad = admission.clone();
    bad.signature = format!(
        "{}AAAA",
        &admission.signature[..admission.signature.len() - 4]
    );
    let check = check_logged_admission(&log, &bad, oracle(session.instances.clone()));
    assert_eq!(check.reason.as_deref(), Some("signature does not verify"));
    assert_eq!(check.verdict, None);
    // Then the log must check too — verdict/passed still propagate.
    let mut broken = log.clone();
    broken["entries"][0]["digest"] = json!("zz");
    let check = check_logged_admission(&broken, &admission, oracle(session.instances.clone()));
    assert_eq!(
        check.reason.as_deref(),
        Some("transparency log failed check: entry 0 has a malformed digest")
    );
    assert_eq!(check.verdict, Some(true));
}

#[test]
fn log_and_admission_verify_under_independent_keys() {
    // The log binds the issuer's history under *its own* key; the admission
    // is bound to the challenges' verifier key. A head signed by a
    // different key than the admission's still checks — the two
    // verifications never compare keys.
    let s1 = session_id(1);
    let session = issue_session(&s1);
    let admission = decide(&session);
    let foreign = log_over(
        &[session_record(&s1), decision_record(&s1)],
        &other_signing(),
    );
    let check = check_log(&foreign);
    assert!(check.ok, "{:?}", check.reason);
    let admitted = check_logged_admission(&foreign, &admission, oracle(session.instances.clone()));
    assert!(admitted.ok, "{:?}", admitted.reason);
    assert_eq!(admitted.verdict, Some(true));
}

// --- TypeScript interop: logs built by bench/tlog.ts -------------------------

#[test]
fn typescript_built_logs_check() {
    for fixture_path in ["ts_tlog_valid.json", "ts_tlog_foreign_head.json"] {
        let log = fixture(fixture_path);
        let check = check_log(&log);
        assert!(check.ok, "{fixture_path} failed: {:?}", check.reason);
        assert_eq!(check.count, Some(5), "{fixture_path}");
        // Every recorded entryHash recomputes through the typed view.
        let typed: TransparencyLog =
            serde_json::from_value(log).unwrap_or_else(|_| panic!("{fixture_path} parses"));
        for entry in &typed.entries {
            assert_eq!(
                entry_hash(&entry.body()),
                entry.entry_hash,
                "{fixture_path}"
            );
        }
    }
}

#[test]
fn typescript_tampered_logs_fail_with_matching_reasons() {
    for (fixture_path, expected) in [
        ("ts_tlog_broken_chain.json", "entry 1 breaks the chain"),
        ("ts_tlog_wrong_index.json", "entry 2 has the wrong index"),
        ("ts_tlog_recompute.json", "entry 1 hash does not recompute"),
        ("ts_tlog_reissued.json", "entry 1 re-issues a session"),
        (
            "ts_tlog_decision_before_session.json",
            "entry 0 decides an unknown or decided session",
        ),
        (
            "ts_tlog_unknown_decision.json",
            "entry 1 decides an unknown or decided session",
        ),
        (
            "ts_tlog_decided_twice.json",
            "entry 2 decides an unknown or decided session",
        ),
        (
            "ts_tlog_bad_count.json",
            "head count does not match entries",
        ),
        (
            "ts_tlog_bad_head.json",
            "head does not match the last entry",
        ),
        ("ts_tlog_bad_issuedat.json", "head issuedAt is malformed"),
        (
            "ts_tlog_bad_keyid.json",
            "verifier keyId does not match the public key",
        ),
        (
            "ts_tlog_bad_signature.json",
            "head signature does not verify",
        ),
    ] {
        let check = check_log(&fixture(fixture_path));
        assert!(!check.ok, "{fixture_path} must fail");
        assert_eq!(reason(&check), expected, "{fixture_path}");
    }
}

#[test]
fn typescript_prove_finds_decided_and_undecided_sessions() {
    let log = fixture("ts_tlog_valid.json");
    let id_at = |index: usize| {
        log["entries"][index]["sessionId"]
            .as_str()
            .unwrap()
            .to_string()
    };
    // Entries 0/1 are the first session's issuance and decision.
    let decided = prove_session(&log, &id_at(0)).unwrap();
    assert_eq!(decided.session_index, 0);
    assert_eq!(decided.decision_index, Some(1));
    // Entry 4 issued a session that was never decided.
    let undecided = prove_session(&log, &id_at(4)).unwrap();
    assert_eq!(undecided.session_index, 4);
    assert_eq!(undecided.decision_index, None);
    // A session id shaped right but absent from the log.
    let absent = format!("{}z", &id_at(0)[..14]);
    let error = prove_session(&log, &absent).unwrap_err();
    assert_eq!(
        error.to_string(),
        format!("session {absent} is not in the log")
    );
}

#[test]
fn typescript_admissions_admit_and_reject_like_the_reference() {
    let log = fixture("ts_tlog_valid.json");
    let admit = |path: &str| {
        let fixture = fixture(path);
        let admission: Admission =
            serde_json::from_value(fixture["admission"].clone()).expect("admission parses");
        let instances: Vec<GeneratedInstance> =
            serde_json::from_value(fixture["instances"].clone()).expect("instances parse");
        check_logged_admission(&log, &admission, oracle(instances))
    };
    // Logged + decided sessions admit; the recorded verdict passes through.
    let check = admit("ts_tlog_admission.json");
    assert_eq!(
        check,
        AdmittedCheck {
            ok: true,
            verdict: Some(true),
            passed: Some(3),
            reason: None,
        }
    );
    let check = admit("ts_tlog_admission_fail.json");
    assert_eq!(
        check,
        AdmittedCheck {
            ok: true,
            verdict: Some(false),
            passed: Some(1),
            reason: None,
        }
    );
    // A valid admission whose sessionId is not in the log is issuer-claimed.
    let check = admit("ts_tlog_admission_unlogged.json");
    assert!(!check.ok);
    assert_eq!(check.verdict, Some(true));
    assert!(check
        .reason
        .as_deref()
        .unwrap_or("")
        .ends_with("is not in the transparency log"));
    // A logged session without a logged decision is not admissible yet.
    let check = admit("ts_tlog_admission_nodecision.json");
    assert!(!check.ok);
    assert!(check
        .reason
        .as_deref()
        .unwrap_or("")
        .ends_with("has no logged decision"));
}

#[test]
fn typescript_foreign_head_still_admits() {
    // The head is signed by a different issuer key than the admission's
    // verifier — the log checks on its own key, the admission on its
    // challenges' key. Independence is the protocol's design: one issuer
    // may rotate log keys without invalidating admissions.
    let log = fixture("ts_tlog_foreign_head.json");
    let fixture = fixture("ts_tlog_admission.json");
    let admission: Admission =
        serde_json::from_value(fixture["admission"].clone()).expect("admission parses");
    let instances: Vec<GeneratedInstance> =
        serde_json::from_value(fixture["instances"].clone()).expect("instances parse");
    let admission_key = serde_json::from_str::<Value>(&admission.payload).unwrap()["challenges"][0]
        ["verifier"]["publicKey"]
        .as_str()
        .unwrap()
        .to_string();
    assert_ne!(
        log["head"]["verifier"]["publicKey"].as_str().unwrap(),
        admission_key
    );
    let check = check_logged_admission(&log, &admission, oracle(instances));
    assert!(check.ok, "{:?}", check.reason);
}
