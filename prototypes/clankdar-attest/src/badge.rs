//! `clankdar-badge-v1` — portable subject badges over signed admissions.
//!
//! A respondent accumulates subject-bound admissions (§7 proofs, from any
//! issuer) under one Ed25519 key and packs them into a self-signed dossier a
//! third party replays without contacting anyone. The subject signs, never an
//! issuer — a badge is a curated claim "these signed episodes are bound to my
//! key", and admissions from different verifier keys mix freely. Optional
//! tlog inclusion proofs tie an admission's session to a logged decision,
//! upgrading issuer-claimed admissions to logged ones.
//!
//! [`check_badge`] independently replays a badge: envelope and payload
//! shape, the `subjectKey` public key, 1–64 members each through the full
//! [`check_admission_with_pool`] replay with distinct `sessionId`s, subject
//! binding (every proof-carrying receipt uses `subjectKey`, and at least one
//! receipt must carry a proof), optional inclusion proofs replayed against
//! their own logs, `issuedAt` shape, and the badge signature over the
//! payload bytes verbatim. Disclosed holdout pools are indexed by `poolKey`
//! — the set may mix issuers — and each admission replays against its
//! matching pool; undisclosed scores stay valid but sum into `unreplayed`.
//!
//! Scope: a badge proves the subject key accumulated these admissions. It
//! does not prove the key holder solved anything — delegation survives
//! aggregation — and it does not prove the admissions were earned: a
//! colluding issuer can self-mint, which is why tlog proofs are optional
//! but recommended. A badge is never identity, liveness, or authority.
//!
//! This module mirrors `bench/badge.ts` in the clankdar repository.

use std::collections::{HashMap, HashSet};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::{
    b64url, b64url_decode, canonical_json, check_admission_with_pool, parse_time, prove_session,
    verifying_key, Admission, AttestError, GeneratedInstance, HoldoutPool, SessionProof,
    TransparencyLog,
};

/// Wire protocol identifier.
pub const BADGE_PROTOCOL: &str = "clankdar-badge-v1";

/// Maximum `admissions` entries (and `proofs`, and disclosed pools) —
/// mirrors `MAX_ADMISSIONS`.
pub const MAX_BADGE_ADMISSIONS: usize = 64;

/// Optional tlog inclusion evidence covering one admission's sessionId
/// (mirrors `BadgeProof`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BadgeProof {
    /// The full transparency log the proof was read from.
    pub log: TransparencyLog,
    /// The claimed `{sessionId, sessionIndex, decisionIndex, head}` —
    /// replayed against a fresh `prove_session` over `log`.
    pub proof: SessionProof,
}

/// The signed body serialized inside [`Badge::payload`] (mirrors
/// `BadgeBody`).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BadgeBody {
    /// Object kind (`"badge"`).
    pub kind: String,
    /// Base64url Ed25519 JWK `x` — the respondent key that signs this badge.
    pub subject_key: String,
    /// 1..=64 subject-bound admissions, from any issuer.
    pub admissions: Vec<Admission>,
    /// Optional tlog inclusion proofs; each names a carried session.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proofs: Option<Vec<BadgeProof>>,
    /// RFC 3339 issuance instant.
    pub issued_at: String,
}

/// A subject-signed badge: `payload` is canonical JSON signed verbatim.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Badge {
    /// Protocol identifier (`clankdar-badge-v1`).
    pub protocol: String,
    /// Canonical JSON of the [`BadgeBody`], signed verbatim.
    pub payload: String,
    /// Base64url Ed25519 signature by `subjectKey` over `payload` bytes.
    pub signature: String,
}

/// Options for [`pack_badge`] (mirrors the `packBadge` options).
pub struct PackBadgeOptions<'a> {
    /// Optional tlog inclusion proofs assembled by the caller
    /// (`tlog build` + `tlog prove`); each must name a carried session.
    pub proofs: Option<&'a [BadgeProof]>,
    /// Disclosed holdout pools, potentially from several issuers, indexed
    /// by `poolKey` during replay.
    pub pools: Option<&'a [HoldoutPool]>,
    /// Issuance instant; `None` uses the wall clock.
    pub now: Option<OffsetDateTime>,
}

/// Pack subject-bound admissions into a badge signed by the subject key —
/// `packBadge` in `bench/badge.ts`. The packed badge is replayed through
/// the independent checker before it is returned — the same rule as a gate
/// issuer re-checking minted receipts — so this function never emits a
/// badge that fails [`check_badge`].
pub fn pack_badge(
    admissions: &[Admission],
    opts: &PackBadgeOptions<'_>,
    key: &SigningKey,
    regenerate: impl Fn(&str, &str, u32, u64) -> Result<GeneratedInstance, String>,
) -> Result<Badge, AttestError> {
    let now = opts.now.unwrap_or_else(OffsetDateTime::now_utc);
    let body = BadgeBody {
        kind: "badge".to_string(),
        subject_key: b64url(&key.verifying_key().to_bytes()),
        admissions: admissions.to_vec(),
        proofs: opts.proofs.map(|proofs| proofs.to_vec()),
        issued_at: now
            .format(&Rfc3339)
            .map_err(|e| AttestError::Malformed(e.to_string()))?,
    };
    let payload = canonical_json(
        &serde_json::to_value(&body).map_err(|e| AttestError::Malformed(e.to_string()))?,
    );
    let signature = b64url(&key.sign(payload.as_bytes()).to_bytes());
    let badge = Badge {
        protocol: BADGE_PROTOCOL.to_string(),
        payload,
        signature,
    };
    let replay = check_badge(
        &serde_json::to_value(&badge).map_err(|e| AttestError::Malformed(e.to_string()))?,
        opts.pools,
        regenerate,
    );
    if !replay.ok {
        return Err(AttestError::Mismatch(format!(
            "packed badge does not verify: {}",
            replay.reason.unwrap_or_default()
        )));
    }
    Ok(badge)
}

/// Outcome of an independent badge check (mirrors `BadgeCheck`).
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct BadgeCheck {
    /// Every verification step passed.
    pub ok: bool,
    /// The badge's subject key (base64url JWK `x`) when `ok` holds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    /// Count of carried admissions when `ok` holds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub admissions: Option<u64>,
    /// Count of admissions whose signed verdict is `pass` when `ok` holds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub passed: Option<u64>,
    /// Count of admissions covered by at least one verified tlog proof
    /// when `ok` holds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logged: Option<u64>,
    /// Held-out receipts whose scores remain issuer-claimed across the
    /// carried admissions — absent when zero, mirroring the TypeScript
    /// `unreplayed` member.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unreplayed: Option<u64>,
    /// Why the check failed when `ok` is false.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl BadgeCheck {
    fn fail(reason: impl Into<String>) -> Self {
        Self {
            ok: false,
            subject: None,
            admissions: None,
            passed: None,
            logged: None,
            unreplayed: None,
            reason: Some(reason.into()),
        }
    }
}

/// `checkBadge`: independently replay a badge — every admission must pass
/// [`check_admission_with_pool`], every admission must be bound to the
/// badge's subject key (every proof-carrying receipt uses `subjectKey`,
/// and an admission with no proof is not bound at all), optional tlog
/// proofs must replay for their own admission's sessionId, and the badge
/// signature must verify over the payload bytes under `subjectKey`.
///
/// `pools` are disclosed holdout pools — the set may mix issuers — indexed
/// by `poolKey`; each admission replays against the pool its `heldout`
/// marker commits, and undisclosed scores stay valid but sum into
/// `unreplayed`. Mirroring the TypeScript checker, each supplied pool is
/// re-parsed through [`HoldoutPool::parse`] (a typed pool whose commitment
/// broke since it was minted fails the check), more than 64 pools are
/// refused, and duplicate `poolKey`s are rejected.
///
/// `badge` is read as raw JSON like the TypeScript checker: a non-object
/// badge, non-string members, or malformed admission/proof members produce
/// structured failures, never a panic. `regenerate` is the same generator
/// oracle the admission check takes — every embedded receipt replays its
/// instance, so the oracle is required.
pub fn check_badge(
    badge: &Value,
    pools: Option<&[HoldoutPool]>,
    regenerate: impl Fn(&str, &str, u32, u64) -> Result<GeneratedInstance, String>,
) -> BadgeCheck {
    let disclosed = pools.unwrap_or(&[]);
    if disclosed.len() > MAX_BADGE_ADMISSIONS {
        return BadgeCheck::fail("pools exceed the admission bound");
    }
    let mut by_key: HashMap<&str, &HoldoutPool> = HashMap::new();
    for pool in disclosed {
        // `parsePool(value)` re-validates inside `checkBadge`, so a pool
        // whose commitment no longer matches its cells fails here rather
        // than silently replaying under a tampered pool.
        let value = serde_json::to_value(pool).unwrap_or(Value::Null);
        if let Err(error) = HoldoutPool::parse(&value) {
            return BadgeCheck::fail(format!("holdout pool does not verify: {error}"));
        }
        if by_key.insert(pool.pool_key.as_str(), pool).is_some() {
            return BadgeCheck::fail("two holdout pools share a poolKey");
        }
    }
    if badge.get("protocol").and_then(Value::as_str) != Some(BADGE_PROTOCOL)
        || badge.get("payload").and_then(Value::as_str).is_none()
        || badge.get("signature").and_then(Value::as_str).is_none()
    {
        return BadgeCheck::fail("not a badge");
    }
    let payload = badge
        .get("payload")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let signature_member = badge
        .get("signature")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let body: Value = match serde_json::from_str(payload) {
        Ok(body) => body,
        Err(_) => return BadgeCheck::fail("payload is not JSON"),
    };
    let subject_key_member = body.get("subjectKey").and_then(Value::as_str);
    if body.get("kind").and_then(Value::as_str) != Some("badge") || subject_key_member.is_none() {
        return BadgeCheck::fail("malformed badge payload");
    }
    let subject_key_member = subject_key_member.unwrap_or_default();
    // `publicJwk` throws on undecodable key material; a bad key is a
    // failed check, not a malformed badge.
    let subject_key = match verifying_key(subject_key_member) {
        Ok(key) => key,
        Err(_) => return BadgeCheck::fail("subjectKey is not an Ed25519 public key"),
    };
    let admissions = match body.get("admissions").and_then(Value::as_array) {
        Some(admissions) if !admissions.is_empty() && admissions.len() <= MAX_BADGE_ADMISSIONS => {
            admissions
        }
        _ => return BadgeCheck::fail("admissions must be 1..64 signed admissions"),
    };
    let mut sessions: HashSet<String> = HashSet::new();
    let mut passed = 0u64;
    let mut unreplayed = 0u64;
    for member in admissions {
        // `!admission || typeof admission !== "object" || typeof
        // admission.payload !== "string"` — arrays count as objects in
        // JavaScript but carry no `payload` member either way, so member
        // access alone decides here.
        let Some(member_payload) = member.get("payload").and_then(Value::as_str) else {
            return BadgeCheck::fail("admission does not verify: not a gate admission");
        };
        let admission_body: Value = match serde_json::from_str(member_payload) {
            Ok(body) => body,
            Err(_) => return BadgeCheck::fail("admission does not verify: payload is not JSON"),
        };
        // Pool selection reads the first challenge carrying a `heldout`
        // member — member presence, not shape — then takes `poolKey` only
        // when it is a string, exactly like the TypeScript checker.
        let heldout = admission_body
            .get("challenges")
            .and_then(Value::as_array)
            .and_then(|challenges| challenges.iter().find_map(|c| c.get("heldout")));
        let pool = heldout
            .and_then(|marker| marker.get("poolKey"))
            .and_then(Value::as_str)
            .and_then(|key| by_key.get(key))
            .copied();
        let admission: Admission = match serde_json::from_value(member.clone()) {
            Ok(admission) => admission,
            Err(_) => return BadgeCheck::fail("admission does not verify: not a gate admission"),
        };
        let check = check_admission_with_pool(&admission, pool, &regenerate);
        if !check.ok {
            return BadgeCheck::fail(format!(
                "admission does not verify: {}",
                check.reason.unwrap_or_default()
            ));
        }
        // A passing admission always carries a well-formed `gs_` session
        // id — the admission check already required it.
        let session_id = admission_body
            .get("sessionId")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if !sessions.insert(session_id.to_string()) {
            return BadgeCheck::fail("two admissions share a session");
        }
        // Subject binding: every embedded receipt that carries a
        // `subjectProof` must use `subjectKey`, and at least one receipt
        // must carry a proof. A present `subjectProof` in a passing
        // admission is always well-formed — the receipt check required it
        // — so `publicKey` is a string here; a malformed proof is the
        // graceful equivalent of the TypeScript `proof.publicKey` member
        // read and compares unequal, never panics.
        let mut bound = false;
        for receipt in admission_body
            .get("receipts")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let receipt_payload = receipt
                .get("payload")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let receipt_body: Value = serde_json::from_str(receipt_payload).unwrap_or(Value::Null);
            let Some(proof) = receipt_body.get("subjectProof") else {
                continue;
            };
            if proof.get("publicKey").and_then(Value::as_str) != Some(subject_key_member) {
                return BadgeCheck::fail("admission is bound to a different subject");
            }
            bound = true;
        }
        if !bound {
            return BadgeCheck::fail("admission is not subject-bound");
        }
        // `if (check.verdict) passed++` — the recorded verdict counts, not
        // the receipt tally.
        if check.verdict == Some(true) {
            passed += 1;
        }
        unreplayed += check.unreplayed.unwrap_or(0);
    }
    let empty = Vec::new();
    let proofs: &[Value] = match body.get("proofs") {
        // `body.proofs ?? []` — absent means no proofs; present-but-not-an-
        // array (including `null`) is malformed.
        None => &empty,
        Some(value) => match value.as_array() {
            Some(proofs) => proofs,
            None => return BadgeCheck::fail("proofs is not an array"),
        },
    };
    if proofs.len() > MAX_BADGE_ADMISSIONS {
        return BadgeCheck::fail("proofs exceed the admission bound");
    }
    let mut logged: HashSet<&str> = HashSet::new();
    for entry in proofs {
        let session_id = match entry
            .get("proof")
            .and_then(|proof| proof.get("sessionId"))
            .and_then(Value::as_str)
        {
            Some(session_id) => session_id,
            None => return BadgeCheck::fail("malformed inclusion proof"),
        };
        if !sessions.contains(session_id) {
            return BadgeCheck::fail("proof names a session the badge does not carry");
        }
        let log = entry.get("log").unwrap_or(&Value::Null);
        let expected = match prove_session(log, session_id) {
            Ok(expected) => expected,
            Err(error) => {
                return BadgeCheck::fail(format!("inclusion proof does not verify: {error}"))
            }
        };
        let proof = entry.get("proof").unwrap_or(&Value::Null);
        // `entry.proof.decisionIndex !== expected.decisionIndex` — strict
        // equality distinguishes `undefined` (member absent → mismatch
        // against anything, even an undecided `null`), `null` (equal only
        // to an undecided expectation), numbers, and non-numeric garbage.
        let decision_matches = match proof.get("decisionIndex") {
            Some(Value::Null) => expected.decision_index.is_none(),
            Some(number @ Value::Number(_)) => {
                number.as_f64() == expected.decision_index.map(|index| index as f64)
            }
            _ => false,
        };
        // The recorded indexes and head must equal a fresh `proveSession`
        // over the carried log. `expected.head` is `log.head` verbatim in
        // TypeScript, so the canonical comparison reads the raw member —
        // never a typed round-trip that could drop forward-compatible
        // members.
        if proof.get("sessionIndex").and_then(Value::as_f64) != Some(expected.session_index as f64)
            || !decision_matches
            || canonical_json(proof.get("head").unwrap_or(&Value::Null))
                != canonical_json(log.get("head").unwrap_or(&Value::Null))
        {
            return BadgeCheck::fail("inclusion proof does not match the log");
        }
        // A badge proof asserts the admission's *decision* is logged —
        // issuance alone is not enough.
        if expected.decision_index.is_none() {
            return BadgeCheck::fail("proof has no logged decision");
        }
        logged.insert(session_id);
    }
    // `Date.parse` is looser than RFC 3339 — exotic-but-parseable stamps
    // ("Sep 18 2026") fail here that JavaScript accepts; packed badges
    // carry `toISOString` output, which parses identically.
    match body.get("issuedAt").and_then(Value::as_str) {
        Some(stamp) if parse_time(stamp).is_ok() => {}
        _ => return BadgeCheck::fail("issuedAt is malformed"),
    }
    // `cryptoVerify` never throws into a hard failure — bad signature
    // material is a failed check.
    let verified = b64url_decode(signature_member)
        .ok()
        .and_then(|bytes| Signature::from_slice(&bytes).ok())
        .map(|signature| subject_key.verify(payload.as_bytes(), &signature).is_ok())
        .unwrap_or(false);
    if !verified {
        return BadgeCheck::fail("badge signature does not verify");
    }
    BadgeCheck {
        ok: true,
        subject: Some(subject_key_member.to_string()),
        admissions: Some(admissions.len() as u64),
        passed: Some(passed),
        logged: Some(logged.len() as u64),
        unreplayed: (unreplayed > 0).then_some(unreplayed),
        reason: None,
    }
}
