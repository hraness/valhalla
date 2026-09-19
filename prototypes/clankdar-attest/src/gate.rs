//! `clankdar-gate-v1` — admission sessions over sealed-seed attestation.
//!
//! A session mints `policy.challenges` sealed challenges under one session id
//! and one deadline. The issuer signs an [`Admission`] binding the complete
//! challenge list, the minted receipts, and the verdict
//! (`passed >= minPass`). [`check_admission`] independently replays an
//! admission — envelope and payload shape, per-challenge session binding and
//! policy coverage, the payload signature, every embedded receipt through
//! the deep regeneration check, receipt-to-challenge canonical equality, one
//! subject key across proofed receipts, and verdict arithmetic — trusting
//! nothing beyond the recorded episode.
//!
//! Scope: an admission attests that one session produced K passing responses
//! under one policy inside one window. It is capability evidence — never
//! identity, liveness, or authority.
//!
//! This module mirrors `bench/gate.ts` in the clankdar repository. One
//! deliberate divergence: the TypeScript `parsePolicy` rejects cells absent
//! from the suite pool, while [`GatePolicy::parse`] validates the
//! `family:tier` shape only — "cell exists" is enforced by receipt
//! regeneration instead, since a receipt for a nonexistent cell fails its
//! own deep check and can never count toward the verdict.

use std::collections::{HashMap, HashSet};

use ed25519_dalek::{Signature, Verifier};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    b64url_decode, canonical_json, check_receipt_deep, is_session_id, key_id_of, parse_time,
    verifying_key, AttestError, Challenge, GeneratedInstance, Receipt, ATTEST_PROTOCOL,
};

/// Wire protocol identifier.
pub const GATE_PROTOCOL: &str = "clankdar-gate-v1";

/// Generator pool version for the `v2` suite.
pub const V2_SUITE_VERSION: &str = "clankdar-suite-v2";
/// Generator pool version for the `frontier` suite.
pub const FRONTIER_SUITE_VERSION: &str = "clankdar-frontier-v1";
/// Generator pool version for the `agent` suite.
pub const AGENT_SUITE_VERSION: &str = "clankdar-agent-v1";

/// Maximum `cells` entries in a policy (mirrors `MAX_CELLS`).
pub const MAX_POLICY_CELLS: usize = 64;
/// Maximum challenges minted per session (mirrors `MAX_CHALLENGES`).
pub const MAX_POLICY_CHALLENGES: u64 = 16;
/// Minimum session TTL in seconds (mirrors the `10` policy floor).
pub const MIN_POLICY_TTL_SECONDS: u64 = 10;
/// Maximum session TTL in seconds (mirrors `MAX_TTL`).
pub const MAX_POLICY_TTL_SECONDS: u64 = 3600;

/// `suiteVersion`: policy suite name → generator pool version. Any other
/// name falls through to the v2 pool, mirroring the TypeScript ternary;
/// [`GatePolicy::parse`] rejects unknown names before this is reached.
pub fn suite_version(suite: &str) -> &'static str {
    match suite {
        "frontier" => FRONTIER_SUITE_VERSION,
        "agent" => AGENT_SUITE_VERSION,
        _ => V2_SUITE_VERSION,
    }
}

/// One gate floor: which cells, how many challenges, how many must pass,
/// how long the session window lasts.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GatePolicy {
    /// Suite name: `"v2"`, `"frontier"`, or `"agent"`.
    pub suite: String,
    /// Cell ids as `"family:tier"`, e.g. `"registervm:t5"`. 1..64 distinct
    /// entries.
    pub cells: Vec<String>,
    /// Challenges minted per session: 1..16, drawn from cells with
    /// replacement.
    pub challenges: u64,
    /// Passing responses required to admit: 1..challenges.
    pub min_pass: u64,
    /// Uniform session deadline in seconds: 10..3600.
    pub ttl_seconds: u64,
}

/// `^([a-z0-9]+):t(\d+)$` — the cell id shape.
fn parse_cell(cell: &str) -> Option<(&str, u64)> {
    let (family, tier) = cell.split_once(':')?;
    if family.is_empty()
        || !family
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
    {
        return None;
    }
    let tier = tier.strip_prefix('t')?;
    if tier.is_empty() || !tier.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some((family, tier.parse().ok()?))
}

/// `Number.isInteger(value)` for a non-negative JSON number: an integral
/// `3.0` counts as the integer `3`, matching JavaScript.
fn js_integer_u64(value: &Value) -> Option<u64> {
    if let Some(u) = value.as_u64() {
        return Some(u);
    }
    let f = value.as_f64()?;
    if f.fract() == 0.0 && f >= 0.0 && f <= u64::MAX as f64 {
        Some(f as u64)
    } else {
        None
    }
}

/// JavaScript `String(value)` / `${value}` coercion for JSON values, used
/// where the TypeScript checker builds `family:tier` cell ids by raw
/// template interpolation. Arrays flatten like `Array.prototype.toString`;
/// objects coerce to `"[object Object]"` — neither can match a cell.
fn js_string(value: Option<&Value>) -> String {
    match value {
        None => "undefined".to_string(),
        Some(Value::Null) => "null".to_string(),
        Some(Value::Bool(b)) => b.to_string(),
        Some(Value::Number(n)) => js_number_string(n),
        Some(Value::String(s)) => s.clone(),
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| js_string(Some(item)))
            .collect::<Vec<_>>()
            .join(","),
        Some(Value::Object(_)) => "[object Object]".to_string(),
    }
}

/// JavaScript `Number.prototype.toString` for JSON numbers: integers print
/// without a decimal point (JS prints `5` for `5.0`). Past `1e21` JS
/// switches to exponential notation — any such string can never equal a
/// `family:t\d+` cell, so Rust's shortest representation is
/// outcome-equivalent there.
fn js_number_string(n: &serde_json::Number) -> String {
    if let Some(u) = n.as_u64() {
        return u.to_string();
    }
    if let Some(i) = n.as_i64() {
        return i.to_string();
    }
    match n.as_f64() {
        Some(f) if f.fract() == 0.0 && f.abs() < 1e21 => format!("{f:.0}"),
        Some(f) => f.to_string(),
        None => n.to_string(),
    }
}

/// JavaScript falsiness for the `!value` checks (`missing`/`null`, `false`,
/// `0`, and `""` are falsy).
fn js_falsy(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => true,
        Some(Value::Bool(b)) => !*b,
        Some(Value::Number(n)) => n.as_f64() == Some(0.0),
        Some(Value::String(s)) => s.is_empty(),
        _ => false,
    }
}

/// JavaScript `===` for JSON values: a missing member is `undefined`, and
/// `undefined === undefined`. Objects and arrays compare by reference in
/// JavaScript, so two distinct parsed objects are never `===` even when
/// their contents agree.
fn js_strict_eq(a: Option<&Value>, b: Option<&Value>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(x), Some(y)) => match (x, y) {
            (Value::Object(_), _) | (Value::Array(_), _) => false,
            (_, Value::Object(_)) | (_, Value::Array(_)) => false,
            _ => x == y,
        },
        _ => false,
    }
}

/// Map key for `challenge.challengeId` mirroring JavaScript `Map`
/// semantics: `undefined` (missing), `null`, numbers, and strings are all
/// distinct keys, so the encoding keeps them apart.
fn member_key(member: Option<&Value>) -> String {
    match member {
        None => "\u{0}undefined".to_string(),
        Some(value) => canonical_json(value),
    }
}

impl GatePolicy {
    /// Strictly parse and bound a gate policy, mirroring `parsePolicy` in
    /// `bench/gate.ts` — except suite-pool membership. The TypeScript side
    /// looks every cell up in the suite pool; this side validates the
    /// `family:tier` shape and defers "cell exists" to receipt
    /// regeneration, which fails for a nonexistent cell anyway.
    pub fn parse(value: &Value) -> Result<Self, AttestError> {
        let fail =
            |message: &str| AttestError::InvalidInput(format!("invalid gate policy: {message}"));
        let object = value
            .as_object()
            .ok_or_else(|| fail("expected an object"))?;
        let suite = match object.get("suite").and_then(Value::as_str) {
            Some(suite @ ("v2" | "frontier" | "agent")) => suite.to_string(),
            _ => return Err(fail("suite must be v2, frontier, or agent")),
        };
        let cells: Vec<String> = match object.get("cells").and_then(Value::as_array) {
            Some(cells)
                if !cells.is_empty()
                    && cells.len() <= MAX_POLICY_CELLS
                    && cells.iter().all(Value::is_string) =>
            {
                cells
                    .iter()
                    .map(|cell| cell.as_str().unwrap_or_default().to_string())
                    .collect()
            }
            _ => return Err(fail("cells must be 1..64 distinct cell ids")),
        };
        if cells.iter().collect::<HashSet<_>>().len() != cells.len() {
            return Err(fail("cells must be distinct"));
        }
        for cell in &cells {
            if parse_cell(cell).is_none() {
                return Err(fail(&format!("unknown cell for suite {suite}: {cell}")));
            }
        }
        let challenges = match object.get("challenges").and_then(js_integer_u64) {
            Some(challenges) if (1..=MAX_POLICY_CHALLENGES).contains(&challenges) => challenges,
            _ => {
                return Err(fail(&format!(
                    "challenges must be 1..{MAX_POLICY_CHALLENGES}"
                )))
            }
        };
        let min_pass = match object.get("minPass").and_then(js_integer_u64) {
            Some(min_pass) if min_pass >= 1 && min_pass <= challenges => min_pass,
            _ => return Err(fail("minPass must be 1..challenges")),
        };
        let ttl_seconds = match object.get("ttlSeconds").and_then(js_integer_u64) {
            Some(ttl) if (MIN_POLICY_TTL_SECONDS..=MAX_POLICY_TTL_SECONDS).contains(&ttl) => ttl,
            _ => {
                return Err(fail(&format!(
                    "ttlSeconds must be {MIN_POLICY_TTL_SECONDS}..{MAX_POLICY_TTL_SECONDS}"
                )))
            }
        };
        Ok(Self {
            suite,
            cells,
            challenges,
            min_pass,
            ttl_seconds,
        })
    }

    /// Validate an already-typed policy with the same bounds as [`Self::parse`].
    pub fn validate(&self) -> Result<(), AttestError> {
        let value =
            serde_json::to_value(self).map_err(|e| AttestError::Malformed(e.to_string()))?;
        Self::parse(&value).map(|_| ())
    }
}

/// The admission verdict recorded inside the signed body.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdmissionVerdict {
    /// `passed >= required`.
    pub pass: bool,
    /// Count of passing receipts.
    pub passed: u64,
    /// Required passing count (`policy.minPass`).
    pub required: u64,
    /// RFC 3339 instant the issuer decided the session.
    pub decided_at: String,
}

/// The signed body serialized inside [`Admission::payload`].
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdmissionBody {
    /// Object kind (`"admission"`).
    pub kind: String,
    /// Session identifier (`gs_` + base64url).
    pub session_id: String,
    /// The gate floor the session ran under.
    pub policy: GatePolicy,
    /// Optional relying-party subject claim shared by every challenge.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    /// Optional application scope binding shared by every challenge.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<String>,
    /// The complete session challenge list — completeness, not receipts,
    /// is the record.
    pub challenges: Vec<Challenge>,
    /// One receipt per answered, format-canonical challenge.
    pub receipts: Vec<Receipt>,
    /// The signed admission verdict.
    pub verdict: AdmissionVerdict,
}

/// A signed admission: `payload` is canonical JSON signed verbatim.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Admission {
    /// Protocol identifier.
    pub protocol: String,
    /// Canonical JSON of the [`AdmissionBody`], signed verbatim.
    pub payload: String,
    /// Base64url Ed25519 signature over `payload` bytes.
    pub signature: String,
}

/// Outcome of an independent admission check (mirrors `AdmissionCheck`).
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AdmissionCheck {
    /// Every verification step passed.
    pub ok: bool,
    /// The recorded admission verdict when `ok` holds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verdict: Option<bool>,
    /// Count of passing receipts when `ok` holds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub passed: Option<u64>,
    /// Why the check failed when `ok` is false.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl AdmissionCheck {
    fn fail(reason: impl Into<String>) -> Self {
        Self {
            ok: false,
            verdict: None,
            passed: None,
            reason: Some(reason.into()),
        }
    }
}

/// Independently replay an admission: payload signature, then every
/// embedded receipt through the deep regeneration check, then session
/// binding, policy coverage, completeness, deadline, and verdict
/// arithmetic. Trusts nothing beyond the recorded episode.
///
/// `regenerate` is the same oracle callback [`crate::check_receipt_deep`]
/// takes — `(suite_version, family, tier, seed) -> instance` — because the
/// TypeScript checker always regenerates inside `checkReceipt`.
///
/// Challenges are checked on the raw parsed payload rather than a typed
/// struct, mirroring the loose member access of `checkAdmission`: unknown
/// members are tolerated, and only the enumerated members are examined.
pub fn check_admission(
    admission: &Admission,
    regenerate: impl Fn(&str, &str, u32, u64) -> Result<GeneratedInstance, String>,
) -> AdmissionCheck {
    if admission.protocol != GATE_PROTOCOL {
        return AdmissionCheck::fail("not a gate admission");
    }
    let body: Value = match serde_json::from_str(&admission.payload) {
        Ok(body) => body,
        Err(_) => return AdmissionCheck::fail("payload is not JSON"),
    };
    let session_id = body.get("sessionId").and_then(Value::as_str);
    if body.get("kind").and_then(Value::as_str) != Some("admission")
        || session_id.is_none_or(|id| !is_session_id(id))
    {
        return AdmissionCheck::fail("malformed admission payload");
    }
    let session_id = session_id.unwrap_or_default();
    let policy = match GatePolicy::parse(body.get("policy").unwrap_or(&Value::Null)) {
        Ok(policy) => policy,
        Err(error) => {
            return AdmissionCheck::fail(format!("invalid embedded policy: {error}"));
        }
    };
    let challenges = match body.get("challenges").and_then(Value::as_array) {
        Some(challenges) if challenges.len() as u64 == policy.challenges => challenges,
        _ => return AdmissionCheck::fail("challenge list does not cover the policy"),
    };
    let version = suite_version(&policy.suite);
    let cells: HashSet<&str> = policy.cells.iter().map(String::as_str).collect();
    let body_subject = body.get("subject");
    let body_context = body.get("context");
    let mut by_id: HashMap<String, &Value> = HashMap::new();
    // `""` initial values, matching the TypeScript falsy accumulators.
    let mut public_key: Option<Value> = Some(Value::String(String::new()));
    let mut expires_at: Option<Value> = Some(Value::String(String::new()));
    for challenge in challenges {
        if challenge.get("protocol").and_then(Value::as_str) != Some(ATTEST_PROTOCOL)
            || challenge.get("kind").and_then(Value::as_str) != Some("challenge")
        {
            return AdmissionCheck::fail("malformed challenge in admission");
        }
        if challenge.get("sessionId").and_then(Value::as_str) != Some(session_id) {
            return AdmissionCheck::fail("challenge is not bound to this session");
        }
        if challenge.get("suiteVersion").and_then(Value::as_str) != Some(version) {
            return AdmissionCheck::fail("challenge suite disagrees with the policy");
        }
        let cell = format!(
            "{}:t{}",
            js_string(challenge.get("family")),
            js_string(challenge.get("tier"))
        );
        if !cells.contains(cell.as_str()) {
            return AdmissionCheck::fail("challenge cell is outside the policy");
        }
        let challenge_expires = challenge.get("expiresAt").cloned();
        if js_falsy(expires_at.as_ref()) {
            expires_at = challenge_expires;
        } else if !js_strict_eq(challenge_expires.as_ref(), expires_at.as_ref()) {
            return AdmissionCheck::fail("session challenges do not share one deadline");
        }
        let challenge_key = challenge
            .get("verifier")
            .and_then(|verifier| verifier.get("publicKey"))
            .filter(|key| !key.is_null())
            .cloned()
            .unwrap_or_else(|| Value::String(String::new()));
        if js_falsy(public_key.as_ref()) {
            public_key = Some(challenge_key.clone());
        } else if !js_strict_eq(Some(&challenge_key), public_key.as_ref()) {
            return AdmissionCheck::fail("session challenges mix verifier keys");
        }
        // The TypeScript `keyIdOf` throws on non-string key material; a
        // failed check is the honest equivalent here.
        let key_id_matches = challenge_key
            .as_str()
            .and_then(|key| key_id_of(key).ok())
            .zip(
                challenge
                    .get("verifier")
                    .and_then(|verifier| verifier.get("keyId"))
                    .and_then(Value::as_str),
            )
            .is_some_and(|(computed, recorded)| computed == recorded);
        if !key_id_matches {
            return AdmissionCheck::fail("verifier keyId does not match the public key");
        }
        // `challenge.subject ?? undefined !== body.subject`: the challenge
        // member normalizes `null` to absent, the body member does not.
        if !js_strict_eq(
            challenge.get("subject").filter(|v| !v.is_null()),
            body_subject,
        ) || !js_strict_eq(
            challenge.get("context").filter(|v| !v.is_null()),
            body_context,
        ) {
            return AdmissionCheck::fail("challenge binding disagrees with the admission");
        }
        if by_id
            .insert(member_key(challenge.get("challengeId")), challenge)
            .is_some()
        {
            return AdmissionCheck::fail("duplicate challenge id");
        }
    }
    let verified = public_key
        .as_ref()
        .and_then(Value::as_str)
        .and_then(|key| verifying_key(key).ok())
        .and_then(|key| {
            b64url_decode(&admission.signature)
                .ok()
                .and_then(|bytes| Signature::from_slice(&bytes).ok())
                .map(|signature| key.verify(admission.payload.as_bytes(), &signature).is_ok())
        })
        .unwrap_or(false);
    if !verified {
        return AdmissionCheck::fail("signature does not verify");
    }
    let receipts = match body.get("receipts").and_then(Value::as_array) {
        Some(receipts) if receipts.len() <= challenges.len() => receipts,
        _ => return AdmissionCheck::fail("malformed receipts"),
    };
    let mut answered = HashSet::new();
    // `let subjectKey: string | undefined` — the one-subject-key rule binds
    // only receipts that carry a proof.
    let mut subject_key: Option<String> = None;
    let mut passed = 0u64;
    for member in receipts {
        let receipt: Receipt = match serde_json::from_value(member.clone()) {
            Ok(receipt) => receipt,
            Err(_) => {
                return AdmissionCheck::fail(
                    "embedded receipt does not verify: not an attestation receipt",
                )
            }
        };
        let replay = check_receipt_deep(&receipt, &regenerate);
        if !replay.ok {
            return AdmissionCheck::fail(format!(
                "embedded receipt does not verify: {}",
                replay.reason.unwrap_or_default()
            ));
        }
        let receipt_body = serde_json::from_str::<Value>(&receipt.payload).ok();
        let receipt_challenge = receipt_body
            .as_ref()
            .and_then(|payload| payload.get("challenge").cloned());
        let listed = receipt_challenge
            .as_ref()
            .and_then(|rc| by_id.get(&member_key(rc.get("challengeId"))));
        let matches = match (&receipt_challenge, listed) {
            (Some(rc), Some(listed)) => canonical_json(listed) == canonical_json(rc),
            _ => false,
        };
        if !matches {
            return AdmissionCheck::fail("receipt is not for a listed session challenge");
        }
        if !answered.insert(member_key(
            receipt_challenge
                .as_ref()
                .and_then(|rc| rc.get("challengeId")),
        )) {
            return AdmissionCheck::fail("two receipts for one challenge");
        }
        // One subject per session: `subjectProof !== undefined` counts a
        // present `null` too, but a malformed proof already failed the deep
        // check above, so a defined proof here carries a string `publicKey`.
        if let Some(proof) = receipt_body
            .as_ref()
            .and_then(|body| body.get("subjectProof"))
        {
            let proof_key = proof.get("publicKey").and_then(Value::as_str);
            if let Some(recorded) = &subject_key {
                if proof_key != Some(recorded.as_str()) {
                    return AdmissionCheck::fail("receipts mix subject keys");
                }
            } else {
                subject_key = proof_key.map(str::to_string);
            }
        }
        if replay.verdict == Some(true) {
            passed += 1;
        }
    }
    // `!verdict` in TypeScript — a falsy verdict member fails the rescore.
    let verdict = body.get("verdict").filter(|v| !js_falsy(Some(*v)));
    let recorded_passed = verdict
        .and_then(|v| v.get("passed"))
        .and_then(Value::as_f64);
    let required = verdict
        .and_then(|v| v.get("required"))
        .and_then(Value::as_f64);
    let pass = verdict.and_then(|v| v.get("pass")).and_then(Value::as_bool);
    if verdict.is_none()
        || recorded_passed != Some(passed as f64)
        || required != Some(policy.min_pass as f64)
        || pass != Some(passed >= policy.min_pass)
    {
        return AdmissionCheck::fail("verdict does not rescore");
    }
    let decided = verdict
        .and_then(|v| v.get("decidedAt"))
        .and_then(Value::as_str)
        .and_then(|stamp| parse_time(stamp).ok());
    // `Date.parse` yields NaN for garbage and `decided > NaN` is false in
    // JavaScript, so an unparseable recorded deadline bounds nothing; the
    // recorded `decidedAt` itself must still parse.
    let expires = expires_at
        .as_ref()
        .and_then(Value::as_str)
        .and_then(|stamp| parse_time(stamp).ok());
    if decided.is_none_or(|d| expires.is_some_and(|e| d > e)) {
        return AdmissionCheck::fail("decision is later than the session deadline");
    }
    AdmissionCheck {
        ok: true,
        verdict: Some(passed >= policy.min_pass),
        passed: Some(passed),
        reason: None,
    }
}
