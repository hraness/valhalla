//! `clankdar-tlog-v1` — a signed transparency log over gate issuance.
//!
//! The gate ledger (`bench/store.ts`) records every session issuance and
//! every admission decision, but only the issuer sees it. The transparency
//! log is the derived, signed view that makes that history enumerable: each
//! ledger record becomes one hash-chained entry — `digest` over the
//! verbatim record, `prev` over the previous entry hash — and the issuer
//! signs a head committing to the entry count and the last `entryHash`, the
//! analogue of a CT signed tree head.
//!
//! [`check_log`] independently replays a log: every `entryHash` recomputes,
//! the `prev` chain walks back to genesis, entry order satisfies ledger
//! semantics (a session is issued once; a decision names an issued,
//! still-open session), then the head is recounted and its `keyId` and
//! signature re-verified. [`prove_session`] reports the session and
//! decision indexes a third party needs as inclusion evidence;
//! [`check_logged_admission`] is the portable-badge test — the admission
//! must verify on its own AND trace to a logged, decided session.
//!
//! Scope: the log binds this issuer's history under its own key. It does
//! not prevent self-minting — a verifier can always answer its own oracle —
//! and it cannot detect a fork alone: equivocation is visible only by
//! comparing heads the issuer published elsewhere. This module only
//! *checks* logs: building one replays the private JSONL ledger, which
//! stays operator-side. [`entries_for`]/[`entry_hash`] exist so tests and
//! tooling can chain already-public records — never for ledger replay.
//!
//! This module mirrors `bench/tlog.ts` in the clankdar repository.

use std::collections::HashSet;

use ed25519_dalek::{Signature, Verifier};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use crate::gate::js_integer_u64;
use crate::{
    b64url_decode, canonical_json, check_admission_with_pool, key_id_of, parse_time, sha256_hex,
    verifying_key, Admission, AdmissionCheck, AttestError, GeneratedInstance, HoldoutPool,
    VerifierRef,
};

/// Wire protocol identifier.
pub const TLOG_PROTOCOL: &str = "clankdar-tlog-v1";

/// `^[0-9a-f]{64}$` — a lowercase SHA-256 hex digest.
fn is_hex64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Chain genesis: the first entry's `prev` (64 zeroes — the TypeScript
/// `"0".repeat(64)`).
fn genesis() -> String {
    "0".repeat(64)
}

/// Deserialize a JSON number with JavaScript integer semantics: JSON
/// numbers are doubles, so an integral `4.0` counts as `4`.
fn de_u64<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Value::deserialize(deserializer)?;
    js_integer_u64(&value).ok_or_else(|| serde::de::Error::custom("not a non-negative integer"))
}

/// The hashed body of one entry — the fields `entryHash` commits to.
/// Serde tolerates unknown members: the protocol permits future fields.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TlogEntry {
    /// Position in the chain; checked against the array index.
    #[serde(deserialize_with = "de_u64")]
    pub index: u64,
    /// `"session"` (issuance) or `"decision"` (admission verdict).
    #[serde(rename = "type")]
    pub kind: String,
    /// Gate session id this entry records.
    pub session_id: String,
    /// SHA-256 hex over `canonical()` of the verbatim ledger record.
    pub digest: String,
    /// Previous entry's `entryHash`; the genesis entry uses 64 zeroes.
    pub prev: String,
}

/// A chained entry: the hashed body plus its `entryHash`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TlogHashedEntry {
    /// Position in the chain; checked against the array index.
    #[serde(deserialize_with = "de_u64")]
    pub index: u64,
    /// `"session"` (issuance) or `"decision"` (admission verdict).
    #[serde(rename = "type")]
    pub kind: String,
    /// Gate session id this entry records.
    pub session_id: String,
    /// SHA-256 hex over `canonical()` of the verbatim ledger record.
    pub digest: String,
    /// Previous entry's `entryHash`; the genesis entry uses 64 zeroes.
    pub prev: String,
    /// SHA-256 hex over `canonical()` of the entry body (excluding
    /// `entryHash`).
    pub entry_hash: String,
}

impl TlogHashedEntry {
    /// The body `entryHash` commits to — the entry minus `entryHash`.
    pub fn body(&self) -> TlogEntry {
        TlogEntry {
            index: self.index,
            kind: self.kind.clone(),
            session_id: self.session_id.clone(),
            digest: self.digest.clone(),
            prev: self.prev.clone(),
        }
    }
}

/// Signed log head — the transparency-log analogue of a CT signed tree
/// head.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TlogHead {
    /// Protocol identifier (`clankdar-tlog-v1`).
    pub protocol: String,
    /// Object kind (`"head"`).
    pub kind: String,
    /// Number of entries this head commits to.
    #[serde(deserialize_with = "de_u64")]
    pub count: u64,
    /// `entryHash` of the last entry (64 zeroes on an empty log).
    pub head: String,
    /// RFC 3339 issuance instant.
    pub issued_at: String,
    /// Issuer key identity; `keyId` recomputes from `publicKey`.
    pub verifier: VerifierRef,
    /// Base64url Ed25519 over `canonical()` of the head excluding
    /// `signature`.
    pub signature: String,
    /// Unknown members ride along verbatim — the TypeScript `prove` echoes
    /// the recorded head object, so forward-compatible members are kept.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// A full `{head, entries}` transparency log.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransparencyLog {
    /// The signed head committing to the entry chain.
    pub head: TlogHead,
    /// The hash-chained entries in ledger order.
    pub entries: Vec<TlogHashedEntry>,
}

/// `entryHashOf`: SHA-256 hex over `canonical()` of the entry body —
/// `index`, `type`, `sessionId`, `digest`, `prev`. `entryHash` itself is
/// never part of its own preimage.
pub fn entry_hash(entry: &TlogEntry) -> String {
    sha256_hex(
        canonical_json(&json!({
            "index": entry.index,
            "type": entry.kind,
            "sessionId": entry.session_id,
            "digest": entry.digest,
            "prev": entry.prev,
        }))
        .as_bytes(),
    )
}

/// `entriesFor`: chain ledger records into entries — `digest` over the
/// verbatim record, `prev` over the previous `entryHash`, genesis 64
/// zeroes. Records arrive as raw JSON so the digest covers them
/// byte-for-byte: `{type:"session", session}` or `{type:"decision",
/// sessionId, admission, receipts}`.
///
/// `sessionId` is read off `session.sessionId` for a session record and off
/// `sessionId` for a decision, mirroring the TypeScript ternary. A
/// malformed record whose `sessionId` is not a string yields the empty
/// string here where TypeScript would carry the verbatim value — the
/// checker is the conformance boundary and rejects empty `sessionId`
/// entries either way.
pub fn entries_for(records: &[Value]) -> Vec<TlogHashedEntry> {
    let mut entries = Vec::with_capacity(records.len());
    let mut prev = genesis();
    for (index, record) in records.iter().enumerate() {
        let kind = record
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let session_id = if kind == "session" {
            record
                .get("session")
                .and_then(|session| session.get("sessionId"))
        } else {
            record.get("sessionId")
        };
        let entry = TlogEntry {
            index: index as u64,
            kind: kind.to_string(),
            session_id: session_id
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            digest: sha256_hex(canonical_json(record).as_bytes()),
            prev: prev.clone(),
        };
        let hashed = TlogHashedEntry {
            entry_hash: entry_hash(&entry),
            index: entry.index,
            kind: entry.kind,
            session_id: entry.session_id,
            digest: entry.digest,
            prev: entry.prev,
        };
        prev = hashed.entry_hash.clone();
        entries.push(hashed);
    }
    entries
}

/// Outcome of an independent transparency-log check (mirrors `LogCheck`).
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct LogCheck {
    /// Every verification step passed.
    pub ok: bool,
    /// Entry count committed under the head when `ok` holds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub count: Option<u64>,
    /// Why the check failed when `ok` is false.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl LogCheck {
    fn fail(reason: impl Into<String>) -> Self {
        Self {
            ok: false,
            count: None,
            reason: Some(reason.into()),
        }
    }
}

/// `headBody`: the canonical head the signature covers — the six recorded
/// members minus `signature`, copied verbatim so unknown members inside
/// `verifier` stay covered while members outside the six are not. JS
/// numbers are doubles, so integral floats are normalized to integers
/// before canonicalizing (`4.0` signs as `4`).
fn head_body(head: &Value) -> Value {
    let mut body = Map::new();
    for member in ["protocol", "kind", "count", "head", "issuedAt", "verifier"] {
        if let Some(value) = head.get(member) {
            body.insert(member.to_string(), js_normalize_numbers(value));
        }
    }
    Value::Object(body)
}

/// Normalize integral JSON floats to integers so `canonical_json` prints
/// the same bytes `canonical()` did: JavaScript has only doubles and
/// `JSON.stringify(4.0)` is `"4"`. Non-integral doubles keep Rust's
/// shortest form — past `1e21` JavaScript switches to exponential notation,
/// an edge no recomputable signed body can carry.
fn js_normalize_numbers(value: &Value) -> Value {
    match value {
        Value::Number(n) => match n.as_f64() {
            Some(f) if f.fract() == 0.0 && f >= 0.0 && f <= u64::MAX as f64 => {
                Value::from(f as u64)
            }
            Some(f) if f.fract() == 0.0 && f >= i64::MIN as f64 && f < 0.0 => Value::from(f as i64),
            _ => value.clone(),
        },
        Value::Array(items) => Value::Array(items.iter().map(js_normalize_numbers).collect()),
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(k, v)| (k.clone(), js_normalize_numbers(v)))
                .collect(),
        ),
        other => other.clone(),
    }
}

/// `checkLog`: independently replay a transparency log — recompute every
/// `entryHash`, walk the `prev` chain from genesis, enforce ledger
/// semantics on entry order (a session is issued once; a decision names an
/// issued, still-open session), then recount and re-verify the head `keyId`
/// and signature. Entries are read by loose member access like the
/// TypeScript checker: unknown members are tolerated and never committed.
///
/// Note `digest` is shape-checked but not recomputed — it covers the
/// private ledger record, which a checker never sees. The chain binds it
/// transitively through `entryHash`.
pub fn check_log(log: &Value) -> LogCheck {
    if !log.is_object() {
        return LogCheck::fail("not a transparency log");
    }
    let Some(entries) = log.get("entries").and_then(Value::as_array) else {
        return LogCheck::fail("entries is not an array");
    };
    let mut issued: HashSet<&str> = HashSet::new();
    let mut decided: HashSet<&str> = HashSet::new();
    let mut prev = genesis();
    for (i, entry) in entries.iter().enumerate() {
        // `!entry || typeof entry !== "object"` — a JS array *is* an
        // object, so array entries fall through to fail the index check.
        if !(entry.is_object() || entry.is_array()) {
            return LogCheck::fail(format!("entry {i} is malformed"));
        }
        // `entry.index !== i` — a JSON number compares by value, so an
        // integral `4.0` counts as `4`; non-numbers never match.
        if entry.get("index").and_then(Value::as_f64) != Some(i as f64) {
            return LogCheck::fail(format!("entry {i} has the wrong index"));
        }
        let kind = entry
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if kind != "session" && kind != "decision" {
            return LogCheck::fail(format!("entry {i} has an unknown type"));
        }
        let session_id = entry
            .get("sessionId")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if session_id.is_empty() {
            return LogCheck::fail(format!("entry {i} has no sessionId"));
        }
        let digest = entry
            .get("digest")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if !is_hex64(digest) {
            return LogCheck::fail(format!("entry {i} has a malformed digest"));
        }
        let entry_prev = entry
            .get("prev")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if !is_hex64(entry_prev) {
            return LogCheck::fail(format!("entry {i} has a malformed prev"));
        }
        let recorded_hash = entry
            .get("entryHash")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if !is_hex64(recorded_hash) {
            return LogCheck::fail(format!("entry {i} has a malformed entryHash"));
        }
        if entry_prev != prev {
            return LogCheck::fail(format!("entry {i} breaks the chain"));
        }
        // The hash input is the five recorded members; the index check
        // above already pinned `entry.index === i`, so the loop index
        // carries the same canonical value (JS prints integral doubles
        // without a fraction).
        let body = TlogEntry {
            index: i as u64,
            kind: kind.to_string(),
            session_id: session_id.to_string(),
            digest: digest.to_string(),
            prev: entry_prev.to_string(),
        };
        if entry_hash(&body) != recorded_hash {
            return LogCheck::fail(format!("entry {i} hash does not recompute"));
        }
        if kind == "session" {
            if !issued.insert(session_id) {
                return LogCheck::fail(format!("entry {i} re-issues a session"));
            }
        } else {
            // `issued`/`decided` only hold earlier entries, so a decision
            // must name a session issued strictly before it — the same
            // referential integrity `GateStore` enforces on the ledger.
            if !issued.contains(session_id) || decided.contains(session_id) {
                return LogCheck::fail(format!("entry {i} decides an unknown or decided session"));
            }
            decided.insert(session_id);
        }
        prev = recorded_hash.to_string();
    }
    let head = log.get("head").unwrap_or(&Value::Null);
    // `!head || typeof head !== "object"` — a JS array is still an object,
    // so it falls through to fail the protocol test rather than "missing".
    if !(head.is_object() || head.is_array()) {
        return LogCheck::fail("head is missing");
    }
    if head.get("protocol").and_then(Value::as_str) != Some(TLOG_PROTOCOL)
        || head.get("kind").and_then(Value::as_str) != Some("head")
    {
        return LogCheck::fail("head is not a tlog head");
    }
    if head.get("count").and_then(Value::as_f64) != Some(entries.len() as f64) {
        return LogCheck::fail("head count does not match entries");
    }
    if head.get("head").and_then(Value::as_str) != Some(prev.as_str()) {
        return LogCheck::fail("head does not match the last entry");
    }
    // `Date.parse` is looser than RFC 3339 — exotic-but-parseable stamps
    // ("Sep 18 2026") fail here that JavaScript accepts; logged heads carry
    // `toISOString` output, which parses identically.
    match head.get("issuedAt").and_then(Value::as_str) {
        Some(stamp) if parse_time(stamp).is_ok() => {}
        _ => return LogCheck::fail("head issuedAt is malformed"),
    }
    let public_key = head
        .get("verifier")
        .and_then(|verifier| verifier.get("publicKey"))
        .and_then(Value::as_str);
    // The TypeScript `keyIdOf` never throws on string material (base64url
    // decodes leniently); a failed recompute is the honest equivalent here
    // — a garbage key can only pass if its misdecoded digest matches the
    // recorded keyId, and then the signature check fails anyway.
    let key_id_matches = public_key
        .and_then(|key| key_id_of(key).ok())
        .zip(
            head.get("verifier")
                .and_then(|verifier| verifier.get("keyId"))
                .and_then(Value::as_str),
        )
        .is_some_and(|(computed, recorded)| computed == recorded);
    if !key_id_matches {
        return LogCheck::fail("verifier keyId does not match the public key");
    }
    // `verifyBodySignature` never throws — bad key material, a non-string
    // signature, or a bad signature is a failed check, never a trap.
    let verifies = public_key
        .and_then(|key| verifying_key(key).ok())
        .zip(head.get("signature").and_then(Value::as_str))
        .and_then(|(key, signature)| {
            b64url_decode(signature)
                .ok()
                .and_then(|bytes| Signature::from_slice(&bytes).ok())
                .map(|signature| {
                    key.verify(canonical_json(&head_body(head)).as_bytes(), &signature)
                        .is_ok()
                })
        })
        .unwrap_or(false);
    if !verifies {
        return LogCheck::fail("head signature does not verify");
    }
    LogCheck {
        ok: true,
        count: Some(entries.len() as u64),
        reason: None,
    }
}

/// Inclusion evidence for one session (mirrors `SessionProof`): the log
/// must check out first, then the session's issuance index and decision
/// index are reported under the signed head.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionProof {
    /// The session id proved.
    pub session_id: String,
    /// Index of the session-issuance entry.
    pub session_index: u64,
    /// Index of the decision entry — `null` while the session is
    /// undecided, matching the TypeScript `decisionIndex: null`.
    pub decision_index: Option<u64>,
    /// The signed head the indexes are read under, echoed verbatim
    /// including any unknown members.
    pub head: TlogHead,
}

/// `proveSession`: run [`check_log`], then report the session's issuance
/// index and decision index under the signed head. A third party checks
/// the log, then this proof, and knows the session was issued and whether
/// its decision was logged.
pub fn prove_session(log: &Value, session_id: &str) -> Result<SessionProof, AttestError> {
    let check = check_log(log);
    if !check.ok {
        return Err(AttestError::Mismatch(format!(
            "transparency log failed check: {}",
            check.reason.unwrap_or_default()
        )));
    }
    let entries = log
        .get("entries")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let index_of = |kind: &str| {
        entries.iter().position(|entry| {
            entry.get("type").and_then(Value::as_str) == Some(kind)
                && entry.get("sessionId").and_then(Value::as_str) == Some(session_id)
        })
    };
    let session_index = index_of("session").ok_or_else(|| {
        AttestError::InvalidInput(format!("session {session_id} is not in the log"))
    })?;
    let head: TlogHead = serde_json::from_value(log.get("head").cloned().unwrap_or(Value::Null))
        .map_err(|e| AttestError::Malformed(format!("cannot read the checked head: {e}")))?;
    Ok(SessionProof {
        session_id: session_id.to_string(),
        session_index: session_index as u64,
        decision_index: index_of("decision").map(|index| index as u64),
        head,
    })
}

/// Outcome of a logged-admission check (mirrors `AdmittedCheck`).
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AdmittedCheck {
    /// The admission verified AND its session is logged and decided.
    pub ok: bool,
    /// The recorded admission verdict when the admission itself checked.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verdict: Option<bool>,
    /// Count of passing receipts when the admission itself checked.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub passed: Option<u64>,
    /// Held-out receipts whose scores remain issuer-claimed without a
    /// disclosed pool.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unreplayed: Option<u64>,
    /// Why the check failed when `ok` is false.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// `checkLoggedAdmission`: the portable-badge test — the admission must
/// pass the admission checker on its own AND its `sessionId` must have both
/// a session entry and a decision entry in a log that itself verifies. A
/// valid admission with no logged session is issuer-claimed only. Without
/// a disclosed holdout pool, held-out scores remain visible in
/// [`AdmittedCheck::unreplayed`].
pub fn check_logged_admission(
    log: &Value,
    admission: &Admission,
    regenerate: impl Fn(&str, &str, u32, u64) -> Result<GeneratedInstance, String>,
) -> AdmittedCheck {
    check_logged_admission_with_pool(log, admission, None, regenerate)
}

/// Pool-aware `checkLoggedAdmission(log, admission, {pool})`. The log and
/// admission signatures remain independent; the pool only upgrades matching
/// held-out scores from issuer-claimed to replayed.
pub fn check_logged_admission_with_pool(
    log: &Value,
    admission: &Admission,
    pool: Option<&HoldoutPool>,
    regenerate: impl Fn(&str, &str, u32, u64) -> Result<GeneratedInstance, String>,
) -> AdmittedCheck {
    let fail = |result: &AdmissionCheck, reason: String| AdmittedCheck {
        ok: false,
        verdict: result.verdict,
        passed: result.passed,
        unreplayed: result.unreplayed,
        reason: Some(reason),
    };
    let result = check_admission_with_pool(admission, pool, regenerate);
    if !result.ok {
        return AdmittedCheck {
            ok: false,
            verdict: None,
            passed: None,
            unreplayed: None,
            reason: result.reason,
        };
    }
    let body: Value = serde_json::from_str(&admission.payload).unwrap_or(Value::Null);
    let session_id = body
        .get("sessionId")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let check = check_log(log);
    if !check.ok {
        return fail(
            &result,
            format!(
                "transparency log failed check: {}",
                check.reason.unwrap_or_default()
            ),
        );
    }
    let entries = log
        .get("entries")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let has = |kind: &str| {
        entries.iter().any(|entry| {
            entry.get("type").and_then(Value::as_str) == Some(kind)
                && entry.get("sessionId").and_then(Value::as_str) == Some(session_id)
        })
    };
    if !has("session") {
        return fail(
            &result,
            format!("session {session_id} is not in the transparency log"),
        );
    }
    if !has("decision") {
        return fail(
            &result,
            format!("session {session_id} has no logged decision"),
        );
    }
    AdmittedCheck {
        ok: true,
        verdict: result.verdict,
        passed: result.passed,
        unreplayed: result.unreplayed,
        reason: None,
    }
}
