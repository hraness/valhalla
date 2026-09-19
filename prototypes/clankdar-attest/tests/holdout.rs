//! Held-out pool (clankdar-holdout-v1) tests: pool commitment, secret-label
//! stream mixing, three-way receipt checking, and `h:` gate cells.
//!
//! A deterministic fake generator stands in for the TypeScript suite: the
//! prompt and answer derive from the requested seed, so a held-out cell
//! (which regenerates under `mixSeed(label, seed)`) produces a different
//! instance than the published stream for the same public seed. Answers are
//! derived from seeds at runtime, never literal.

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
const SESSION: &str = "gs_aaaaaaaaaaaa";

fn at(iso: &str) -> OffsetDateTime {
    OffsetDateTime::parse(iso, &Rfc3339).unwrap()
}

fn signing() -> SigningKey {
    SigningKey::from_bytes(&[7u8; 32])
}

/// A secret label satisfying `^[A-Za-z0-9_-]{22,128}$`.
fn label(suffix: &str) -> String {
    format!("held-out-secret-label-{suffix}")
}

/// The fake generator oracle: prompt and answer derive from the seed, so
/// `mixSeed` decorrelation shows up as different prompts for one public
/// seed. The answer is derived from the seed, never a literal.
fn fake_oracle(
    suite_version: &str,
    family: &str,
    tier: u32,
    seed: u64,
) -> Result<GeneratedInstance, String> {
    match family {
        "cryptarithm" | "registervm" | "automata" => Ok(GeneratedInstance {
            suite_version: suite_version.to_string(),
            family: family.to_string(),
            tier,
            seed,
            prompt: format!("{family} puzzle t{tier} for seed {seed}"),
            // Integer format for cryptarithm/registervm, bits for automata.
            answer: if family == "automata" {
                format!("{:04b}", seed % 16)
            } else {
                format!("{}", seed % 1_000_000)
            },
        }),
        _ => Err(format!("no instance for {family}:t{tier} seed {seed}")),
    }
}

fn make_pool(suite: &str, cells: &[(&str, u64, &str)]) -> HoldoutPool {
    let cells: Vec<HoldoutCell> = cells
        .iter()
        .map(|(family, tier, label)| HoldoutCell {
            family: family.to_string(),
            tier: *tier,
            label: label.to_string(),
        })
        .collect();
    HoldoutPool {
        protocol: HOLDOUT_PROTOCOL.to_string(),
        suite: suite.to_string(),
        pool_key: pool_key_of(suite, &cells),
        cells,
    }
}

/// Mint a held-out challenge + ticket for `family:tier` under `pool`.
fn issue_held(
    pool: &HoldoutPool,
    family: &str,
    tier: u32,
    seed: u64,
) -> (Challenge, Ticket, GeneratedInstance) {
    let key = signing();
    let cell = holdout_cell(pool, family, tier as u64).expect("cell in pool");
    let instance = holdout_instance(pool, cell, seed, fake_oracle).expect("regenerates");
    let opts = IssueOptions {
        family,
        tier,
        ttl_seconds: Some(300),
        context: None,
        subject: None,
        session_id: Some(SESSION.to_string()),
        holdout_pool: Some(pool),
        now: Some(at(NOW)),
    };
    let (challenge, ticket) = issue_challenge(&opts, seed, &instance, &key).unwrap();
    (challenge, ticket, instance)
}

// --- pool parsing and commitment -------------------------------------------

#[test]
fn pool_parses_and_recommits() {
    let pool = make_pool(
        "frontier",
        &[
            ("cryptarithm", 6, &label("one")),
            ("registervm", 5, &label("two")),
        ],
    );
    let parsed = HoldoutPool::parse(&serde_json::to_value(&pool).unwrap()).unwrap();
    assert_eq!(parsed.suite, "frontier");
    assert_eq!(parsed.cells.len(), 2);
    assert_eq!(parsed.pool_key.len(), 64);
    assert!(parsed.pool_key.chars().all(|c| c.is_ascii_hexdigit()));
    // The commitment covers protocol, suite, and cells — canonical, so a
    // reordered pool object parses identically.
    let reordered = json!({
        "cells": serde_json::to_value(&pool.cells).unwrap(),
        "poolKey": pool.pool_key,
        "suite": "frontier",
        "protocol": HOLDOUT_PROTOCOL,
    });
    assert!(HoldoutPool::parse(&reordered).is_ok());
    // Unknown members are tolerated.
    let mut extended = serde_json::to_value(&pool).unwrap();
    extended["futureMember"] = json!({"anything": 1});
    assert!(HoldoutPool::parse(&extended).is_ok());
}

#[test]
fn pool_rejects_bad_shape_and_commitment() {
    let good =
        serde_json::to_value(make_pool("frontier", &[("cryptarithm", 6, &label("a"))])).unwrap();
    for bad in [
        json!(null),
        json!({"protocol": "clankdar-attest-v1", "suite": "frontier"}),
        json!({"protocol": HOLDOUT_PROTOCOL, "suite": "typo"}),
        json!({"protocol": HOLDOUT_PROTOCOL, "suite": "frontier", "cells": []}),
        json!({"protocol": HOLDOUT_PROTOCOL, "suite": "frontier", "cells": [{"family": "cryptarithm", "tier": 6}]}),
    ] {
        assert!(HoldoutPool::parse(&bad).is_err(), "accepted {bad}");
    }
    // A tampered poolKey or cell list breaks the commitment.
    for (member, value) in [("poolKey", json!("f".repeat(64))), ("suite", json!("v2"))] {
        let mut bad = good.clone();
        bad[member] = value;
        assert!(
            HoldoutPool::parse(&bad).is_err(),
            "accepted {member} tamper"
        );
    }
    // Labels must match the 22..128 base64url shape.
    for bad_label in [
        "short",
        "has spaces inside the label ok",
        &"x".repeat(200),
        "label/with/slashes+padding==",
    ] {
        let mut bad = good.clone();
        bad["cells"][0]["label"] = json!(bad_label);
        // Recommit so the poolKey is honest — the label check must fire.
        let cells: Vec<HoldoutCell> =
            serde_json::from_value(bad["cells"].clone()).unwrap_or_default();
        if cells.len() == 1 {
            bad["poolKey"] = json!(pool_key_of("frontier", &cells));
            assert!(
                HoldoutPool::parse(&bad).is_err(),
                "accepted label {bad_label}"
            );
        }
    }
    // Duplicate cell ids are rejected even with an honest commitment.
    let mut bad = good.clone();
    bad["cells"] = json!([bad["cells"][0].clone(), bad["cells"][0].clone()]);
    let cells: Vec<HoldoutCell> = serde_json::from_value(bad["cells"].clone()).unwrap();
    bad["poolKey"] = json!(pool_key_of("frontier", &cells));
    assert!(HoldoutPool::parse(&bad).is_err());
}

#[test]
fn mix_seed_decorrelates_streams() {
    // Empty label leaves the FNV offset basis: seed ^ 0x811c9dc5.
    assert_eq!(mix_seed("", 0), 0x811c9dc5);
    let seed = 424242;
    let a = mix_seed(&label("a"), seed);
    let b = mix_seed(&label("b"), seed);
    assert_ne!(a, b);
    assert_ne!(a, seed);
    assert!(a <= u32::MAX as u64 && b <= u32::MAX as u64);
    // Same label, different seeds still decorrelate.
    assert_ne!(mix_seed(&label("a"), seed + 1), a);
    // Deterministic: identical inputs mix identically.
    assert_eq!(mix_seed(&label("a"), seed), a);
}

// --- held-out issuance and receipt checking ---------------------------------

#[test]
fn held_out_challenges_carry_the_pool_marker_and_a_decorrelated_prompt() {
    let pool = make_pool("frontier", &[("cryptarithm", 6, &label("a"))]);
    let seed = 424242;
    let (challenge, ticket, held) = issue_held(&pool, "cryptarithm", 6, seed);
    assert_eq!(challenge.heldout, Some(json!({"poolKey": pool.pool_key})));
    // The instance came from the mixed stream — not the published one.
    let published = fake_oracle(FRONTIER_SUITE_VERSION, "cryptarithm", 6, seed).unwrap();
    assert_ne!(held.prompt, published.prompt);
    assert_ne!(held.answer, published.answer);
    // The recorded seed stays the public caller seed.
    assert_eq!(held.seed, seed);
    assert_eq!(ticket.seed, seed);
}

#[test]
fn a_held_out_receipt_checks_three_ways() {
    let pool = make_pool("frontier", &[("cryptarithm", 6, &label("a"))]);
    let key = signing();
    let seed = 424242;
    let (_, ticket, instance) = issue_held(&pool, "cryptarithm", 6, seed);
    // The answer is derived from the seed at runtime, never a literal.
    let response = ticket.expected.clone();
    let receipt =
        verify_response(&ticket, &response, &instance, &key, None, Some(at(LATER))).unwrap();

    // With the committed pool: fully replayed — prompt, answer, rescore.
    let with = check_receipt_with_pool(&receipt, Some(&pool), fake_oracle);
    assert!(with.ok, "with pool: {:?}", with.reason);
    assert_eq!(with.verdict, Some(true));
    assert_eq!(with.replayable, None);

    // Without the pool: the envelope verifies but the score is
    // issuer-claimed.
    let without = check_receipt_with_pool(&receipt, None, fake_oracle);
    assert!(without.ok, "without pool: {:?}", without.reason);
    assert_eq!(without.verdict, Some(true));
    assert_eq!(without.replayable, Some(false));

    // The shallow offline check reports the same unreplayed outcome.
    let shallow = check_receipt(&receipt);
    assert!(shallow.ok);
    assert_eq!(shallow.replayable, Some(false));

    // A foreign pool (different poolKey) is no better than none.
    let foreign = make_pool("frontier", &[("cryptarithm", 6, &label("other"))]);
    let mismatched = check_receipt_with_pool(&receipt, Some(&foreign), fake_oracle);
    assert!(mismatched.ok);
    assert_eq!(mismatched.replayable, Some(false));

    // A pool claiming the marker's key but lacking the cell proves
    // fabrication — a hard failure, not an unreplayed pass.
    let wrong_cells = HoldoutPool {
        pool_key: pool.pool_key.clone(),
        cells: vec![HoldoutCell {
            family: "registervm".to_string(),
            tier: 5,
            label: label("x"),
        }],
        ..pool.clone()
    };
    let hard = check_receipt_with_pool(&receipt, Some(&wrong_cells), fake_oracle);
    assert!(!hard.ok);
    assert_eq!(
        hard.reason.as_deref(),
        Some("held-out cell is not in the committed pool")
    );

    // A malformed marker fails rather than silently degrading.
    let mut body: Value = serde_json::from_str(&receipt.payload).unwrap();
    body["challenge"]["heldout"] = json!({"poolKey": "not-hex"});
    let payload = canonical_json(&body);
    let bad = Receipt {
        payload: payload.clone(),
        signature: URL_SAFE_NO_PAD.encode(key.sign(payload.as_bytes()).to_bytes()),
        ..receipt.clone()
    };
    let result = check_receipt_with_pool(&bad, Some(&pool), fake_oracle);
    assert!(!result.ok);
    assert_eq!(result.reason.as_deref(), Some("malformed heldout marker"));
}

#[test]
fn a_held_out_score_is_issuer_claimed_without_the_pool() {
    // Even a receipt whose recorded pair does not rescore stays `ok` when
    // the cell is held out and the pool is absent — the verdict is
    // issuer-claimed, so checkers never adjudicate it.
    let pool = make_pool("frontier", &[("cryptarithm", 6, &label("a"))]);
    let key = signing();
    let seed = 424242;
    let (_, ticket, instance) = issue_held(&pool, "cryptarithm", 6, seed);
    let receipt = verify_response(
        &ticket,
        &ticket.expected,
        &instance,
        &key,
        None,
        Some(at(LATER)),
    )
    .unwrap();
    let mut body: Value = serde_json::from_str(&receipt.payload).unwrap();
    // Flip the recorded verdict; the envelope re-signs honestly.
    body["verdict"]["pass"] = json!(false);
    let payload = canonical_json(&body);
    let flipped = Receipt {
        payload: payload.clone(),
        signature: URL_SAFE_NO_PAD.encode(key.sign(payload.as_bytes()).to_bytes()),
        ..receipt.clone()
    };
    let result = check_receipt_with_pool(&flipped, None, fake_oracle);
    assert!(result.ok, "{:?}", result.reason);
    assert_eq!(result.verdict, Some(false));
    assert_eq!(result.replayable, Some(false));
    // With the pool the same receipt fails its rescore — the issuer claim
    // is adjudicated only when the stream replays.
    let adjudicated = check_receipt_with_pool(&flipped, Some(&pool), fake_oracle);
    assert!(!adjudicated.ok);
    assert_eq!(
        adjudicated.reason.as_deref(),
        Some("verdict does not rescore")
    );
}

#[test]
fn issue_requires_the_pool_to_cover_the_cell_and_suite() {
    let pool = make_pool("frontier", &[("cryptarithm", 6, &label("a"))]);
    let key = signing();
    let seed = 424242;
    // A cell the pool does not carry refuses at issuance.
    let instance = fake_oracle(FRONTIER_SUITE_VERSION, "registervm", 5, seed).unwrap();
    let opts = IssueOptions {
        family: "registervm",
        tier: 5,
        ttl_seconds: Some(300),
        context: None,
        subject: None,
        session_id: None,
        holdout_pool: Some(&pool),
        now: Some(at(NOW)),
    };
    assert!(issue_challenge(&opts, seed, &instance, &key).is_err());
    // A pool minted for another suite refuses too.
    let v2_pool = make_pool("v2", &[("cryptarithm", 6, &label("a"))]);
    let instance = fake_oracle(FRONTIER_SUITE_VERSION, "cryptarithm", 6, seed).unwrap();
    let opts = IssueOptions {
        family: "cryptarithm",
        tier: 6,
        holdout_pool: Some(&v2_pool),
        ..IssueOptions {
            family: "cryptarithm",
            tier: 6,
            ttl_seconds: Some(300),
            context: None,
            subject: None,
            session_id: None,
            holdout_pool: Some(&v2_pool),
            now: Some(at(NOW)),
        }
    };
    assert!(issue_challenge(&opts, seed, &instance, &key).is_err());
}

// --- `h:` gate policy cells ---------------------------------------------------

#[test]
fn policy_parses_holdout_cells_and_binds_the_pool() {
    // Without a pool only the shape is bound-checked — membership stays
    // unverifiable until the challenge list is examined.
    let policy = GatePolicy::parse(&json!({
        "suite": "frontier",
        "cells": ["cryptarithm:t6", "h:registervm:t5"],
        "challenges": 2, "minPass": 1, "ttlSeconds": 300,
    }))
    .unwrap();
    assert_eq!(policy.cells.len(), 2);

    let pool = make_pool("frontier", &[("registervm", 5, &label("a"))]);
    // The matching pool validates membership.
    GatePolicy::parse_with_pool(
        &json!({
            "suite": "frontier",
            "cells": ["h:registervm:t5"],
            "challenges": 1, "minPass": 1, "ttlSeconds": 300,
        }),
        Some(&pool),
    )
    .unwrap();
    // A pool for another suite refuses.
    let v2_pool = make_pool("v2", &[("registervm", 5, &label("a"))]);
    assert!(GatePolicy::parse_with_pool(
        &json!({
            "suite": "frontier",
            "cells": ["h:registervm:t5"],
            "challenges": 1, "minPass": 1, "ttlSeconds": 300,
        }),
        Some(&v2_pool),
    )
    .is_err());
    // A pool lacking the named cell refuses.
    let other_pool = make_pool("frontier", &[("cryptarithm", 6, &label("a"))]);
    assert!(GatePolicy::parse_with_pool(
        &json!({
            "suite": "frontier",
            "cells": ["h:registervm:t5"],
            "challenges": 1, "minPass": 1, "ttlSeconds": 300,
        }),
        Some(&other_pool),
    )
    .is_err());
    // Malformed `h:` ids fail the shape checks.
    for cell in ["h:", "h::t5", "h:Bad:t5", "h:registervm", "h:registervm:t"] {
        let bad = json!({
            "suite": "frontier", "cells": [cell],
            "challenges": 1, "minPass": 1, "ttlSeconds": 300,
        });
        assert!(GatePolicy::parse(&bad).is_err(), "accepted {cell}");
    }
}

/// Mint a session through the library `issue_session`; `pick` chooses the
/// cell index per challenge (a `Cell` counter alternates deterministically).
fn issue_held_session(
    cells: &[&str],
    challenges: u64,
    min_pass: u64,
    pool: Option<&HoldoutPool>,
    pick: &dyn Fn(usize) -> usize,
) -> (GateSession, Vec<Challenge>) {
    let policy = GatePolicy {
        suite: "frontier".to_string(),
        cells: cells.iter().map(|c| c.to_string()).collect(),
        challenges,
        min_pass,
        ttl_seconds: 300,
    };
    issue_session(
        &policy,
        &IssueSessionOptions {
            subject: None,
            context: None,
            pool,
            now: Some(at(NOW)),
            pick: Some(pick),
            seed_base: Some(424_000),
        },
        &signing(),
        fake_oracle,
    )
    .unwrap()
}

/// A picker that cycles cells in order — `Fn`-compatible via `Cell`.
fn cycling() -> impl Fn(usize) -> usize {
    let counter = std::cell::Cell::new(0usize);
    move |bound| {
        let pick = counter.get() % bound;
        counter.set(counter.get() + 1);
        pick
    }
}

#[test]
fn session_issue_requires_the_pool_for_held_out_cells() {
    let policy = GatePolicy {
        suite: "frontier".to_string(),
        cells: vec!["h:cryptarithm:t6".to_string()],
        challenges: 1,
        min_pass: 1,
        ttl_seconds: 300,
    };
    let result = issue_session(
        &policy,
        &IssueSessionOptions {
            subject: None,
            context: None,
            pool: None,
            now: Some(at(NOW)),
            pick: None,
            seed_base: None,
        },
        &signing(),
        fake_oracle,
    );
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("no holdout pool"));
}

#[test]
fn a_mixed_session_marks_only_held_out_challenges() {
    let pool = make_pool("frontier", &[("registervm", 5, &label("a"))]);
    let (session, challenges) = issue_held_session(
        &["cryptarithm:t6", "h:registervm:t5"],
        4,
        1,
        Some(&pool),
        &cycling(),
    );
    assert_eq!(challenges.len(), 4);
    // The cycling pick alternates published/held-out cells; only the
    // held-out ones carry the marker.
    for (i, challenge) in challenges.iter().enumerate() {
        if i % 2 == 0 {
            assert_eq!(challenge.family, "cryptarithm");
            assert_eq!(challenge.heldout, None);
        } else {
            assert_eq!(challenge.family, "registervm");
            assert_eq!(challenge.heldout, Some(json!({"poolKey": pool.pool_key})));
        }
    }
    assert!(session.tickets.iter().all(|t| t.seed >= 424_000));
}

#[test]
fn a_held_out_admission_replays_with_and_without_the_pool() {
    let pool = make_pool("frontier", &[("registervm", 5, &label("a"))]);
    let key = signing();
    let (session, _challenges) =
        issue_held_session(&["h:registervm:t5"], 2, 1, Some(&pool), &cycling());
    // The answer is derived from the seed at runtime, never a literal.
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
            pool: Some(&pool),
            now: Some(at(LATER)),
        },
        &key,
        fake_oracle,
    )
    .unwrap();

    // Without the pool every receipt verifies but stays issuer-claimed.
    let without = check_admission_with_pool(&admission, None, fake_oracle);
    assert!(without.ok, "without pool: {:?}", without.reason);
    assert_eq!(without.verdict, Some(true));
    assert_eq!(without.passed, Some(2));
    assert_eq!(without.unreplayed, Some(2));

    // With the pool the stream replays fully — no unreplayed count.
    let with = check_admission_with_pool(&admission, Some(&pool), fake_oracle);
    assert!(with.ok, "with pool: {:?}", with.reason);
    assert_eq!(with.verdict, Some(true));
    assert_eq!(with.passed, Some(2));
    assert_eq!(with.unreplayed, None);
}

#[test]
fn held_out_marker_rules_apply_per_challenge() {
    let pool = make_pool("frontier", &[("registervm", 5, &label("a"))]);
    let key = signing();
    let (session, _challenges) = issue_held_session(
        &["cryptarithm:t6", "h:registervm:t5"],
        4,
        1,
        Some(&pool),
        &cycling(),
    );
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
            pool: Some(&pool),
            now: Some(at(LATER)),
        },
        &key,
        fake_oracle,
    )
    .unwrap();
    let body: Value = serde_json::from_str(&admission.payload).unwrap();

    // A `heldout` marker on a published-policy challenge is outside the
    // policy.
    let mut tampered = body.clone();
    tampered["challenges"][0]["heldout"] = json!({"poolKey": pool.pool_key});
    // The receipt for that challenge embeds the unmarked challenge, so it
    // no longer matches — the marker check must fire first.
    let check =
        check_admission_with_pool(&resign_admission(&tampered, &key), Some(&pool), fake_oracle);
    assert!(!check.ok);
    assert_eq!(
        check.reason.as_deref(),
        Some("challenge cell is outside the policy")
    );

    // Dropping the marker off a held-out challenge puts it outside the
    // policy too (the `h:` cell does not cover an unmarked challenge).
    let mut tampered = body.clone();
    let marked = tampered["challenges"]
        .as_array()
        .unwrap()
        .iter()
        .position(|c| c.get("heldout").is_some())
        .expect("a held-out challenge");
    tampered["challenges"][marked]
        .as_object_mut()
        .unwrap()
        .remove("heldout");
    let check =
        check_admission_with_pool(&resign_admission(&tampered, &key), Some(&pool), fake_oracle);
    assert!(!check.ok);
    assert_eq!(
        check.reason.as_deref(),
        Some("challenge cell is outside the policy")
    );

    // Two different pool keys inside one admission mix pools.
    let other = make_pool("frontier", &[("registervm", 5, &label("b"))]);
    let mut tampered = body.clone();
    tampered["challenges"][marked]["heldout"] = json!({"poolKey": other.pool_key});
    let check =
        check_admission_with_pool(&resign_admission(&tampered, &key), Some(&pool), fake_oracle);
    assert!(!check.ok);
    assert_eq!(
        check.reason.as_deref(),
        Some("held-out challenges mix pools")
    );

    // A malformed marker fails its own check.
    let mut tampered = body.clone();
    tampered["challenges"][marked]["heldout"] = json!("not-an-object");
    let check =
        check_admission_with_pool(&resign_admission(&tampered, &key), Some(&pool), fake_oracle);
    assert!(!check.ok);
    assert_eq!(check.reason.as_deref(), Some("malformed heldout marker"));

    // Sanity: the untampered admission still checks.
    let good = check_admission_with_pool(&admission, Some(&pool), fake_oracle);
    assert!(good.ok, "{:?}", good.reason);
}

/// Re-sign a tampered admission payload so a check isolates the tampered
/// member rather than the payload signature.
fn resign_admission(body: &Value, key: &SigningKey) -> Admission {
    let payload = canonical_json(body);
    Admission {
        protocol: GATE_PROTOCOL.to_string(),
        signature: URL_SAFE_NO_PAD.encode(key.sign(payload.as_bytes()).to_bytes()),
        payload,
    }
}

// --- TypeScript interop: admissions minted by bench/gate.ts + holdout.ts ------

/// A lookup oracle over a fixture's recorded generator output — the same
/// `(suite_version, family, tier, seed)` contract `bench/instance.ts` fills.
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

/// TypeScript-issued held-out admissions replay in Rust in both modes:
/// without the pool every held-out receipt verifies but stays
/// issuer-claimed (`unreplayed`); with the committed pool the whole
/// session replays.
#[test]
fn typescript_held_out_admissions_check_both_ways() {
    for (fixture, unreplayed) in [
        ("tests/fixtures/ts_admission_holdout.json", 2),
        ("tests/fixtures/ts_admission_holdout_mixed.json", 1),
    ] {
        let text = std::fs::read_to_string(fixture).expect("fixture missing");
        let fixture: Value = serde_json::from_str(&text).expect("fixture parses");
        let admission: Admission =
            serde_json::from_value(fixture["admission"].clone()).expect("admission parses");
        let pool = HoldoutPool::parse(&fixture["pool"]).expect("pool parses");
        let instances: Vec<GeneratedInstance> =
            serde_json::from_value(fixture["instances"].clone()).expect("instances parse");

        let without = check_admission_with_pool(&admission, None, oracle(instances.clone()));
        assert!(without.ok, "{fixture} without pool: {:?}", without.reason);
        assert_eq!(without.verdict, Some(true), "{fixture}");
        assert_eq!(without.unreplayed, Some(unreplayed), "{fixture}");

        let with = check_admission_with_pool(&admission, Some(&pool), oracle(instances.clone()));
        assert!(with.ok, "{fixture} with pool: {:?}", with.reason);
        assert_eq!(with.verdict, Some(true), "{fixture}");
        assert_eq!(with.unreplayed, None, "{fixture}");
    }
}
