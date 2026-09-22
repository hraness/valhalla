//! Bounded views of voluntarily shared signed admissions, never a complete
//! attempt history, intelligence ranking, identity credential or authority.
//! Issuer result times and the observer's clock remain explicitly separate.
//!
//! JSON parsing retains serde_json's last-member semantics, matching the current
//! reference JSON.parse path; this module does not reject duplicate object keys.
//! Signatures and evidence identity cover the verbatim signed payload bytes.
//! No canonical re-encoding is substituted before signature verification.
use crate::{
    b64url, b64url_decode, canonical_json, check_admission_with_pool, check_badge, parse_time,
    sha256_hex, verifying_key, Admission, GatePolicy, GeneratedInstance, HoldoutPool,
    BADGE_PROTOCOL, GATE_PROTOCOL,
};
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use time::{format_description::well_known::Rfc3339, Duration, OffsetDateTime};

/// Maximum supplied files and total embedded admissions, including duplicates.
pub const MAX_HISTORY_RECORDS: usize = 64;
/// Maximum encoded bytes for one admission before any replay.
pub const MAX_HISTORY_ADMISSION_BYTES: usize = 256 * 1024;
/// Maximum aggregate input bytes before JSON allocation or generator work.
pub const MAX_HISTORY_BYTES: usize = 8 * 1024 * 1024;
/// Maximum rows in one deterministic page.
pub const MAX_HISTORY_PAGE: usize = 16;
const MAX_LOG_ENTRIES: usize = 4096;

/// Pins must be supplied independently of the untrusted history artifacts.
#[derive(Clone, Debug)]
pub struct HistoryExpectation {
    /// Full canonical base64url Ed25519 issuer key, never a truncated key ID.
    pub issuer_key: String,
    /// Full subject key expected in a badge/proof or explicitly issuer-claimed.
    pub subject_key: String,
    /// Exact expected context; None requires its absence, not a wildcard.
    pub context: Option<String>,
    /// Exact expected parsed policy; no implicit acceptance of a stronger floor.
    pub policy: GatePolicy,
    /// Inclusive age limit relative to the injected observer clock.
    pub max_age_seconds: u32,
    /// Maximum accepted issuer future skew; at most one hour.
    pub future_skew_seconds: u32,
}

/// Every view contains only evidence supplied to this call; omissions are unknown.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoryCoverage {
    /// Voluntarily shared records, not all sessions or all attempts.
    PartialShared,
}
/// What links the full subject key to this evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoryBinding {
    /// Only the issuer's signed subject field names this key.
    IssuerClaimed,
    /// A valid old proof signs the session identifier, not the answer bytes.
    SessionAuthorized,
    /// A subject-signed badge endorses the exact carried signed admissions.
    /// It does not prove answer authorship, model identity or submission time.
    BadgeEndorsed,
}
/// History admission checks always request full replay; no shallow success exists.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum HistoryReplay {
    /// All present receipts regenerated; zero-answer failures have zero solves.
    IndependentlyReplayed,
    /// These signed held-out scores could not regenerate without their pool.
    HeldoutUnreplayed {
        /// Number of issuer-claimed receipt scores in this admission.
        receipts: u64,
    },
}
/// A valid signed result's outcome is distinct from evidence validity.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoryOutcome {
    /// The checked admission met its recorded, pinned policy threshold.
    Pass,
    /// The checked admission did not meet the policy threshold.
    Fail,
}
/// Outcome for one listed puzzle, separate from the overall gate verdict.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoryChallengeOutcome {
    /// The checked receipt records a passing answer; consult replay separately.
    Pass,
    /// The checked receipt records a nonpassing answer.
    Fail,
    /// No response receipt was carried for this listed challenge.
    Unanswered,
}
/// Verification scope for one challenge, without exposing its answer or prompt.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoryChallengeReplay {
    /// Its receipt was independently regenerated under the selected evaluator.
    IndependentlyReplayed,
    /// Its signed score remains issuer-claimed without the matching hidden pool.
    HeldoutUnreplayed,
    /// There is no receipt or score to replay for this challenge.
    NoResponse,
}
/// A small summary extracted only after the admission's full verification.
#[derive(Clone, Debug, Serialize)]
pub struct HistoryChallenge {
    challenge_id: String,
    suite_version: String,
    family: String,
    tier: u32,
    outcome: HistoryChallengeOutcome,
    replay: HistoryChallengeReplay,
}
impl HistoryChallenge {
    /// The exact checked challenge identifier.
    pub fn challenge_id(&self) -> &str {
        &self.challenge_id
    }
    /// Generator suite recorded by the checked challenge.
    pub fn suite_version(&self) -> &str {
        &self.suite_version
    }
    /// Puzzle family, without its prompt, answer or private pool label.
    pub fn family(&self) -> &str {
        &self.family
    }
    /// Puzzle difficulty tier within the pinned policy.
    pub const fn tier(&self) -> u32 {
        self.tier
    }
    /// Per-challenge outcome; an absent response is never a scored failure.
    pub const fn outcome(&self) -> HistoryChallengeOutcome {
        self.outcome
    }
    /// Per-challenge replay evidence, including unanswered/hidden-pool cases.
    pub const fn replay(&self) -> HistoryChallengeReplay {
        self.replay
    }
}
/// One checked admission; fields cannot be constructed as verified by callers.
#[derive(Clone, Debug, Serialize)]
pub struct HistoryRecord {
    signed_evidence_hash: String,
    source_hashes: Vec<String>,
    issuer_key: String,
    subject_key: String,
    binding: HistoryBinding,
    session_id: String,
    context: Option<String>,
    policy_hash: String,
    issuer_decided_at: String,
    expires_at: String,
    outcome: HistoryOutcome,
    passed: u64,
    required: u64,
    challenge_count: usize,
    challenges: Vec<HistoryChallenge>,
    answered_receipts: usize,
    replay: HistoryReplay,
    recent: bool,
    conflicted: bool,
    #[serde(skip)]
    decided: OffsetDateTime,
}
impl HistoryRecord {
    /// Hash of protocol, verbatim signed payload and signature. Outer JSON
    /// whitespace changes a source hash, never the attempt identity.
    pub fn signed_evidence_hash(&self) -> &str {
        &self.signed_evidence_hash
    }
    /// SHA-256 of exact supplied file bytes carrying this record.
    pub fn source_hashes(&self) -> &[String] {
        &self.source_hashes
    }
    /// Full independently pinned issuer key.
    pub fn issuer_key(&self) -> &str {
        &self.issuer_key
    }
    /// Full expected subject key; consult binding before interpreting it.
    pub fn subject_key(&self) -> &str {
        &self.subject_key
    }
    /// Exact scope of the key proof, separate from result validity.
    pub const fn binding(&self) -> HistoryBinding {
        self.binding
    }
    /// Signed session ID; scope uniqueness by the full issuer key.
    pub fn session_id(&self) -> &str {
        &self.session_id
    }
    /// Signed issuer decision time, not an independent time attestation.
    pub fn issuer_decided_at(&self) -> &str {
        &self.issuer_decided_at
    }
    /// Signed deadline; expiration does not invalidate retained historical evidence.
    pub fn expires_at(&self) -> &str {
        &self.expires_at
    }
    /// Checked pass or fail; both remain visible.
    pub const fn outcome(&self) -> HistoryOutcome {
        self.outcome
    }
    /// At most16 puzzle summaries in the admission's original challenge order.
    pub fn challenges(&self) -> &[HistoryChallenge] {
        &self.challenges
    }
    /// Generator replay scope, never inferred merely from a valid signature.
    pub const fn replay(&self) -> HistoryReplay {
        self.replay
    }
    /// Whether the result falls within this snapshot's observer-clock age window.
    pub const fn recent(&self) -> bool {
        self.recent
    }
    /// Competing valid signed payloads for this issuer/session are retained;
    /// neither arrival order nor timestamps select a winner.
    pub const fn conflicted(&self) -> bool {
        self.conflicted
    }
}
/// An input or carried admission that could not enter the verified view.
#[derive(Clone, Debug, Serialize)]
pub struct HistoryRejection {
    /// Exact supplied file hash, for locating the original evidence.
    pub source_hash: String,
    /// Carried signed evidence hash when its envelope could be parsed.
    pub signed_evidence_hash: Option<String>,
    /// Checker/pin/time refusal. This is not a recorded failed puzzle attempt.
    pub reason: String,
}
/// An opaque page position tied to the exact snapshot, pins and observer clock.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct HistoryCursor {
    snapshot: String,
    offset: usize,
}
impl HistoryCursor {
    /// Bounded portable cursor encoding for a CLI; it grants no authority.
    pub fn encode(&self) -> String {
        format!("{}:{}", self.snapshot, self.offset)
    }
    /// Parse canonical syntax; page() still checks the exact snapshot and range.
    pub fn decode(raw: &str) -> Result<Self, HistoryError> {
        if raw.len() > 68 {
            return Err(HistoryError::Cursor);
        }
        let (snapshot, number) = raw.split_once(':').ok_or(HistoryError::Cursor)?;
        if snapshot.len() != 64
            || !snapshot
                .bytes()
                .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v))
        {
            return Err(HistoryError::Cursor);
        }
        let offset = number.parse::<usize>().map_err(|_| HistoryError::Cursor)?;
        if offset > MAX_HISTORY_RECORDS || number != offset.to_string() {
            return Err(HistoryError::Cursor);
        }
        Ok(Self {
            snapshot: snapshot.to_string(),
            offset,
        })
    }
}
/// One small page. The parent snapshot's rejections/conflicts remain available.
#[derive(Clone, Debug, Serialize)]
pub struct HistoryPage {
    records: Vec<HistoryRecord>,
    next: Option<HistoryCursor>,
}
impl HistoryPage {
    /// Checked rows in deterministic result-time order.
    pub fn records(&self) -> &[HistoryRecord] {
        &self.records
    }
    /// Continue only against the same snapshot and fixed observer clock.
    pub fn next(&self) -> Option<&HistoryCursor> {
        self.next.as_ref()
    }
    /// Offset for a CLI that displays the accompanying snapshot hash.
    pub fn next_offset(&self) -> Option<usize> {
        self.next.as_ref().map(|next| next.offset)
    }
}
/// A fixed bounded observation; completeness and model identity are not inferred.
#[derive(Clone, Debug, Serialize)]
pub struct HistorySnapshot {
    coverage: HistoryCoverage,
    observed_at: String,
    snapshot_hash: String,
    records: Vec<HistoryRecord>,
    rejected: Vec<HistoryRejection>,
    duplicate_count: usize,
    conflict_count: usize,
}
impl HistorySnapshot {
    /// Always partial shared history, even when every supplied artifact verifies.
    pub const fn coverage(&self) -> HistoryCoverage {
        self.coverage
    }
    /// Clock injected by the caller; never file mtime or issuer-generated export time.
    pub fn observed_at(&self) -> &str {
        &self.observed_at
    }
    /// Exact source/pin/clock identity used by page cursors.
    pub fn snapshot_hash(&self) -> &str {
        &self.snapshot_hash
    }
    /// At most64 validated admissions; includes stale and conflicted records.
    pub fn records(&self) -> &[HistoryRecord] {
        &self.records
    }
    /// Rejected artifacts remain distinguishable from verified failed outcomes.
    pub fn rejected(&self) -> &[HistoryRejection] {
        &self.rejected
    }
    /// Repeated copies of the same exact signed admission counted once.
    pub const fn duplicate_count(&self) -> usize {
        self.duplicate_count
    }
    /// Distinct full-issuer/session groups containing competing verified signed
    /// evidence. Conflicting rows never contribute to subject-bound totals.
    pub const fn conflicts(&self) -> usize {
        self.conflict_count
    }

    /// Count recent, conflict-free, independently replayed sessions with a subject
    /// session proof or badge endorsement. This is not an intelligence score.
    /// Issuer-only zero-answer failures remain visible but are excluded here.
    pub fn subject_bound_outcomes(&self) -> (usize, usize) {
        let mut pass = 0;
        let mut fail = 0;
        for row in &self.records {
            if row.recent
                && !row.conflicted
                && row.binding != HistoryBinding::IssuerClaimed
                && row.replay == HistoryReplay::IndependentlyReplayed
            {
                match row.outcome {
                    HistoryOutcome::Pass => pass += 1,
                    HistoryOutcome::Fail => fail += 1,
                }
            }
        }
        (pass, fail)
    }
    /// Stateless offset page against this exact in-memory snapshot.
    pub fn page_offset(&self, offset: usize, limit: usize) -> Result<HistoryPage, HistoryError> {
        self.page(
            Some(&HistoryCursor {
                snapshot: self.snapshot_hash.clone(),
                offset,
            }),
            limit,
        )
    }
    /// Read at most16 records. Changed source, pins, clock or verification result
    /// invalidates a cursor instead of silently skipping or repeating records.
    pub fn page(
        &self,
        cursor: Option<&HistoryCursor>,
        limit: usize,
    ) -> Result<HistoryPage, HistoryError> {
        if limit == 0 || limit > MAX_HISTORY_PAGE {
            return Err(HistoryError::Bounds);
        }
        let start = if let Some(cursor) = cursor {
            if cursor.snapshot != self.snapshot_hash || cursor.offset > self.records.len() {
                return Err(HistoryError::Cursor);
            }
            cursor.offset
        } else {
            0
        };
        let end = start.saturating_add(limit).min(self.records.len());
        Ok(HistoryPage {
            records: self.records[start..end].to_vec(),
            next: (end < self.records.len()).then(|| HistoryCursor {
                snapshot: self.snapshot_hash.clone(),
                offset: end,
            }),
        })
    }
}
/// Whole-call refusal before verification, distinct from individual bad evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HistoryError {
    /// Input bytes, file/admission count, page size or proof work exceeds a bound.
    Bounds,
    /// Expected key, policy, scope or caller-clock window is malformed.
    Expectations(String),
    /// Cursor is malformed, foreign or outside this snapshot.
    Cursor,
}
impl std::fmt::Display for HistoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "history: {self:?}")
    }
}
impl std::error::Error for HistoryError {}

/// Verify existing admissions or subject-signed badges using the existing deep
/// checker. The oracle must itself enforce a runtime/output budget and use the
/// pinned evaluator; this pure API cannot interrupt a caller's blocking closure.
/// At most64 admissions/16 receipts are considered; optional badge checks replay
/// their carried admissions a second time, still under those explicit bounds.
/// No raw private keys, network access or writes are needed.
pub fn check_history(
    inputs: &[&[u8]],
    expected: &HistoryExpectation,
    observed_at: OffsetDateTime,
    pools: Option<&[HoldoutPool]>,
    regenerate: impl Fn(&str, &str, u32, u64) -> Result<GeneratedInstance, String>,
) -> Result<HistorySnapshot, HistoryError> {
    validate_expectations(expected)?;
    if inputs.len() > MAX_HISTORY_RECORDS
        || pools.is_some_and(|v| v.len() > MAX_HISTORY_RECORDS)
        || inputs
            .iter()
            .try_fold(0usize, |n, bytes| n.checked_add(bytes.len()))
            .is_none_or(|n| n > MAX_HISTORY_BYTES)
    {
        return Err(HistoryError::Bounds);
    }
    let mut pool_keys = BTreeSet::new();
    let mut pool_bytes = 0usize;
    for pool in pools.unwrap_or_default() {
        let value = serde_json::to_value(pool).map_err(|_| HistoryError::Bounds)?;
        pool_bytes = pool_bytes
            .checked_add(
                serde_json::to_vec(&value)
                    .map_err(|_| HistoryError::Bounds)?
                    .len(),
            )
            .ok_or(HistoryError::Bounds)?;
        if pool_bytes > MAX_HISTORY_BYTES {
            return Err(HistoryError::Bounds);
        }
        HoldoutPool::parse(&value)
            .map_err(|e| HistoryError::Expectations(format!("holdout pool: {e}")))?;
        if !pool_keys.insert(&pool.pool_key) {
            return Err(HistoryError::Expectations(
                "duplicate holdout pool commitment".to_string(),
            ));
        }
    }
    let now = observed_at
        .format(&Rfc3339)
        .map_err(|e| HistoryError::Expectations(e.to_string()))?;
    let latest = observed_at
        .checked_add(Duration::seconds(i64::from(expected.future_skew_seconds)))
        .ok_or(HistoryError::Bounds)?;
    let oldest = observed_at
        .checked_sub(Duration::seconds(i64::from(expected.max_age_seconds)))
        .ok_or(HistoryError::Bounds)?;
    let mut parsed = Vec::new();
    let mut rejections = Vec::new();
    let mut count = 0usize;
    let mut source_hashes = Vec::new();
    // Preflight every byte/count bound before any expensive replay, including
    // duplicates and invalid inputs. No one large late file escapes the budget.
    for bytes in inputs {
        let hash = sha256_hex(bytes);
        source_hashes.push(hash.clone());
        let value: Value = match serde_json::from_slice(bytes) {
            Ok(value) => value,
            Err(_) => {
                rejections.push(reject(&hash, None, "input is not JSON"));
                continue;
            }
        };
        match value.get("protocol").and_then(Value::as_str) {
            Some(GATE_PROTOCOL) => {
                preflight_admission(&value)?;
                count += 1;
            }
            Some(BADGE_PROTOCOL) => {
                count = count
                    .checked_add(preflight_badge(&value)?)
                    .ok_or(HistoryError::Bounds)?;
            }
            _ => {
                rejections.push(reject(
                    &hash,
                    None,
                    "expected a gate admission or badge, not an API wrapper",
                ));
                continue;
            }
        }
        if count > MAX_HISTORY_RECORDS {
            return Err(HistoryError::Bounds);
        }
        parsed.push((hash, value));
    }
    let mut rows = BTreeMap::<String, HistoryRecord>::new();
    let mut duplicate_count = 0usize;
    let mut attempts = BTreeMap::<(String, String), BTreeSet<String>>::new();
    for (hash, value) in parsed {
        let mut admissions = Vec::new();
        let badge = value.get("protocol").and_then(Value::as_str) == Some(BADGE_PROTOCOL);
        if badge {
            let body: Value = serde_json::from_str(value["payload"].as_str().unwrap_or(""))
                .unwrap_or(Value::Null);
            if body["subjectKey"].as_str() != Some(expected.subject_key.as_str()) {
                rejections.push(reject(&hash, None, "badge subject key does not match"));
                continue;
            }
            let checked = check_badge(&value, pools, &regenerate);
            if !checked.ok {
                rejections.push(reject(
                    &hash,
                    None,
                    &format!(
                        "badge did not verify: {}",
                        checked.reason.unwrap_or_default()
                    ),
                ));
                continue;
            }
            let stamp = body["issuedAt"].as_str().and_then(|v| parse_time(v).ok());
            if stamp.is_none_or(|stamp| stamp > latest) {
                rejections.push(reject(
                    &hash,
                    None,
                    "badge issuance is malformed or in the future",
                ));
                continue;
            }
            admissions.extend(body["admissions"].as_array().into_iter().flatten().cloned());
        } else {
            admissions.push(value);
        }
        for value in admissions {
            let mut checker = MemberCheck {
                expected,
                oldest,
                latest,
                pools,
                regenerate: &regenerate,
                attempts: &mut attempts,
            };
            match checker.check(&value, &hash, badge) {
                Ok(row) => {
                    if let Some(old) = rows.get_mut(&row.signed_evidence_hash) {
                        duplicate_count += 1;
                        old.binding = old.binding.max(row.binding);
                        if !old.source_hashes.contains(&hash) {
                            old.source_hashes.push(hash.clone());
                            old.source_hashes.sort();
                        }
                    } else {
                        rows.insert(row.signed_evidence_hash.clone(), row);
                    }
                }
                Err(reason) => rejections.push(reject(&hash, signed_hash(&value), &reason)),
            }
        }
    }
    let conflict_count = attempts
        .values()
        .filter(|identities| identities.len() > 1)
        .count();
    let mut records: Vec<_> = rows.into_values().collect();
    for row in &mut records {
        row.conflicted = attempts[&(row.issuer_key.clone(), row.session_id.clone())].len() > 1;
    }
    records.sort_by(|a, b| {
        b.decided
            .cmp(&a.decided)
            .then_with(|| a.issuer_key.cmp(&b.issuer_key))
            .then_with(|| a.session_id.cmp(&b.session_id))
            .then_with(|| a.signed_evidence_hash.cmp(&b.signed_evidence_hash))
    });
    let fingerprint = json!({"sources": source_hashes, "issuer": expected.issuer_key, "subject": expected.subject_key,
        "context": expected.context, "policy": expected.policy, "maxAge": expected.max_age_seconds,
        "skew": expected.future_skew_seconds, "observedAt": now, "records": records, "rejected": rejections});
    Ok(HistorySnapshot {
        coverage: HistoryCoverage::PartialShared,
        observed_at: now,
        snapshot_hash: sha256_hex(canonical_json(&fingerprint).as_bytes()),
        records,
        rejected: rejections,
        duplicate_count,
        conflict_count,
    })
}

fn validate_expectations(expected: &HistoryExpectation) -> Result<(), HistoryError> {
    for key in [&expected.issuer_key, &expected.subject_key] {
        let bytes = b64url_decode(key).map_err(|e| HistoryError::Expectations(e.to_string()))?;
        let parsed = verifying_key(key).map_err(|e| HistoryError::Expectations(e.to_string()))?;
        if bytes.len() != 32 || b64url(&bytes) != *key || parsed.is_weak() {
            return Err(HistoryError::Expectations(
                "expected key must be canonical and nonweak".to_string(),
            ));
        }
    }
    if expected
        .context
        .as_ref()
        .is_some_and(|value| value.len() > crate::MAX_CONTEXT_LEN)
        || expected.future_skew_seconds > 3600
    {
        return Err(HistoryError::Expectations(
            "context or future skew is out of bounds".to_string(),
        ));
    }
    expected
        .policy
        .validate()
        .map_err(|e| HistoryError::Expectations(e.to_string()))
}
fn preflight_admission(value: &Value) -> Result<(), HistoryError> {
    if serde_json::to_vec(value)
        .map_err(|_| HistoryError::Bounds)?
        .len()
        > MAX_HISTORY_ADMISSION_BYTES
    {
        return Err(HistoryError::Bounds);
    }
    if let Some(payload) = value.get("payload").and_then(Value::as_str) {
        if let Ok(body) = serde_json::from_str::<Value>(payload) {
            for field in ["challenges", "receipts"] {
                if body
                    .get(field)
                    .and_then(Value::as_array)
                    .is_some_and(|items| items.len() > 16)
                {
                    return Err(HistoryError::Bounds);
                }
            }
        }
    }
    Ok(())
}
fn preflight_badge(value: &Value) -> Result<usize, HistoryError> {
    let Some(payload) = value.get("payload").and_then(Value::as_str) else {
        return Ok(0);
    };
    let Ok(body) = serde_json::from_str::<Value>(payload) else {
        return Ok(0);
    };
    let members = body.get("admissions").and_then(Value::as_array);
    if members.is_some_and(|members| members.len() > MAX_HISTORY_RECORDS) {
        return Err(HistoryError::Bounds);
    }
    for admission in members.into_iter().flatten() {
        preflight_admission(admission)?;
    }
    if let Some(proofs) = body.get("proofs").and_then(Value::as_array) {
        if proofs.len() > MAX_HISTORY_RECORDS {
            return Err(HistoryError::Bounds);
        }
        let mut entries = 0usize;
        for proof in proofs {
            entries = entries
                .checked_add(
                    proof
                        .get("log")
                        .and_then(|log| log.get("entries"))
                        .and_then(Value::as_array)
                        .map_or(0, Vec::len),
                )
                .ok_or(HistoryError::Bounds)?;
            if entries > MAX_LOG_ENTRIES {
                return Err(HistoryError::Bounds);
            }
        }
    }
    Ok(members.map_or(0, Vec::len))
}
fn signed_hash(value: &Value) -> Option<String> {
    let protocol = value.get("protocol")?.as_str()?;
    let payload = value.get("payload")?.as_str()?;
    let signature = value.get("signature")?.as_str()?;
    Some(sha256_hex(
        canonical_json(&json!([
            "clankdar/history/signed-evidence/v1",
            protocol,
            payload,
            signature
        ]))
        .as_bytes(),
    ))
}
fn reject(source: &str, signed: Option<String>, reason: &str) -> HistoryRejection {
    HistoryRejection {
        source_hash: source.to_string(),
        signed_evidence_hash: signed,
        reason: reason.to_string(),
    }
}
struct MemberCheck<'a, F> {
    expected: &'a HistoryExpectation,
    oldest: OffsetDateTime,
    latest: OffsetDateTime,
    pools: Option<&'a [HoldoutPool]>,
    regenerate: &'a F,
    attempts: &'a mut BTreeMap<(String, String), BTreeSet<String>>,
}
impl<F> MemberCheck<'_, F>
where
    F: Fn(&str, &str, u32, u64) -> Result<GeneratedInstance, String>,
{
    fn check(
        &mut self,
        value: &Value,
        source_hash: &str,
        badge: bool,
    ) -> Result<HistoryRecord, String> {
        let expected = self.expected;
        let oldest = self.oldest;
        let latest = self.latest;
        let pools = self.pools;
        let regenerate = self.regenerate;
        let admission: Admission =
            serde_json::from_value(value.clone()).map_err(|_| "malformed admission envelope")?;
        let body: Value = serde_json::from_str(&admission.payload)
            .map_err(|_| "admission payload is not JSON")?;
        let challenges = body
            .get("challenges")
            .and_then(Value::as_array)
            .ok_or("missing challenges")?;
        if challenges.is_empty()
            || challenges.iter().any(|challenge| {
                challenge
                    .get("verifier")
                    .and_then(|v| v.get("publicKey"))
                    .and_then(Value::as_str)
                    != Some(expected.issuer_key.as_str())
            })
        {
            return Err("issuer does not match the full pinned key".to_string());
        }
        let context_matches = match &expected.context {
            Some(context) => body.get("context").and_then(Value::as_str) == Some(context.as_str()),
            None => body.get("context").is_none(),
        };
        let policy = GatePolicy::parse(body.get("policy").ok_or("missing policy")?)
            .map_err(|e| format!("unsupported or malformed policy: {e}"))?;
        let heldout = challenges
            .iter()
            .find_map(|challenge| challenge.get("heldout"));
        let pool = heldout
            .and_then(|marker| marker.get("poolKey"))
            .and_then(Value::as_str)
            .and_then(|key| {
                pools
                    .unwrap_or_default()
                    .iter()
                    .find(|pool| pool.pool_key == key)
            });
        let check = check_admission_with_pool(&admission, pool, regenerate);
        if !check.ok {
            return Err(format!(
                "admission did not verify: {}",
                check.reason.unwrap_or_default()
            ));
        }
        // A competing authenticated admission remains equivocation evidence even
        // if local context, policy, subject or clock pins exclude it from the view.
        self.attempts
            .entry((
                expected.issuer_key.clone(),
                body["sessionId"]
                    .as_str()
                    .ok_or("missing checked session id")?
                    .to_string(),
            ))
            .or_default()
            .insert(signed_hash(value).ok_or("missing signed identity")?);
        if !context_matches {
            return Err("context does not match the exact expected scope".to_string());
        }
        if policy != expected.policy {
            return Err("policy does not match the expected floor".to_string());
        }
        let receipts = body
            .get("receipts")
            .and_then(Value::as_array)
            .ok_or("missing receipts")?;
        let mut subject_proven = false;
        let mut receipt_bodies = Vec::new();
        for receipt in receipts {
            let receipt_body: Value = serde_json::from_str(
                receipt
                    .get("payload")
                    .and_then(Value::as_str)
                    .ok_or("missing receipt payload")?,
            )
            .map_err(|_| "receipt payload is not JSON")?;
            if let Some(proof) = receipt_body.get("subjectProof") {
                if proof.get("publicKey").and_then(Value::as_str)
                    != Some(expected.subject_key.as_str())
                {
                    return Err("session proof belongs to a different subject key".to_string());
                }
                subject_proven = true;
            }
            receipt_bodies.push(receipt_body);
        }
        let binding = if badge {
            HistoryBinding::BadgeEndorsed
        } else if subject_proven {
            HistoryBinding::SessionAuthorized
        } else if body.get("subject").and_then(Value::as_str) == Some(expected.subject_key.as_str())
        {
            HistoryBinding::IssuerClaimed
        } else {
            return Err(
                "admission neither proves nor issuer-claims the expected subject key".to_string(),
            );
        };
        let decided_text = body
            .get("verdict")
            .and_then(|v| v.get("decidedAt"))
            .and_then(Value::as_str)
            .ok_or("missing decision time")?;
        let decided = parse_time(decided_text).map_err(|_| "malformed issuer decision time")?;
        let expires_text = challenges[0]
            .get("expiresAt")
            .and_then(Value::as_str)
            .ok_or("missing expiry")?;
        let expires = parse_time(expires_text).map_err(|_| "malformed issuer expiry")?;
        let start = expires
            .checked_sub(Duration::seconds(
                i64::try_from(policy.ttl_seconds).map_err(|_| "TTL overflow")?,
            ))
            .ok_or("session window overflow")?;
        if decided < start || decided > expires || decided > latest {
            return Err(
                "issuer decision is outside its session window or allowed future skew".to_string(),
            );
        }
        for challenge in challenges {
            let other = challenge
                .get("expiresAt")
                .and_then(Value::as_str)
                .and_then(|value| parse_time(value).ok())
                .ok_or("malformed challenge expiry")?;
            if other != expires {
                return Err("challenge expiry differs from the session deadline".to_string());
            }
        }
        for receipt in &receipt_bodies {
            let answered = receipt
                .get("verdict")
                .and_then(|v| v.get("answeredAt"))
                .and_then(Value::as_str)
                .and_then(|value| parse_time(value).ok())
                .ok_or("malformed answer time")?;
            if answered < start || answered > decided || answered > latest {
                return Err("issuer answer time is outside the session/decision window".to_string());
            }
        }
        let unreplayed = check.unreplayed.unwrap_or_default();
        Ok(HistoryRecord {
            signed_evidence_hash: signed_hash(value).ok_or("missing signed envelope identity")?,
            source_hashes: vec![source_hash.to_string()],
            issuer_key: expected.issuer_key.clone(),
            subject_key: expected.subject_key.clone(),
            binding,
            session_id: body
                .get("sessionId")
                .and_then(Value::as_str)
                .ok_or("missing session id")?
                .to_string(),
            context: expected.context.clone(),
            policy_hash: sha256_hex(
                canonical_json(&serde_json::to_value(&policy).map_err(|_| "policy cannot encode")?)
                    .as_bytes(),
            ),
            issuer_decided_at: decided_text.to_string(),
            expires_at: expires_text.to_string(),
            outcome: if check.verdict == Some(true) {
                HistoryOutcome::Pass
            } else {
                HistoryOutcome::Fail
            },
            passed: check.passed.ok_or("missing checked pass count")?,
            required: policy.min_pass,
            challenge_count: challenges.len(),
            challenges: challenge_summaries(challenges, &receipt_bodies, pool.is_some())?,
            answered_receipts: receipts.len(),
            replay: if unreplayed == 0 {
                HistoryReplay::IndependentlyReplayed
            } else {
                HistoryReplay::HeldoutUnreplayed {
                    receipts: unreplayed,
                }
            },
            recent: decided >= oldest,
            conflicted: false,
            decided,
        })
    }
}

// Full admission checking has already established exact listed-challenge equality,
// unique challenge IDs/receipts, valid signed verdicts and the one-pool rule.
// This projection adds no replay calls and includes only existing verified fields.
fn challenge_summaries(
    challenges: &[Value],
    receipts: &[Value],
    pool_available: bool,
) -> Result<Vec<HistoryChallenge>, String> {
    challenges
        .iter()
        .map(|challenge| {
            let id = challenge["challengeId"]
                .as_str()
                .ok_or("challenge ID is not text")?;
            let receipt = receipts
                .iter()
                .find(|receipt| receipt["challenge"]["challengeId"].as_str() == Some(id));
            let (outcome, replay) = if let Some(receipt) = receipt {
                let outcome = match receipt["verdict"]["pass"].as_bool() {
                    Some(true) => HistoryChallengeOutcome::Pass,
                    Some(false) => HistoryChallengeOutcome::Fail,
                    None => return Err("checked receipt has no boolean verdict".to_string()),
                };
                let replay = if challenge.get("heldout").is_some() && !pool_available {
                    HistoryChallengeReplay::HeldoutUnreplayed
                } else {
                    HistoryChallengeReplay::IndependentlyReplayed
                };
                (outcome, replay)
            } else {
                (
                    HistoryChallengeOutcome::Unanswered,
                    HistoryChallengeReplay::NoResponse,
                )
            };
            Ok(HistoryChallenge {
                challenge_id: id.to_string(),
                suite_version: challenge["suiteVersion"]
                    .as_str()
                    .ok_or("suite is not text")?
                    .to_string(),
                family: challenge["family"]
                    .as_str()
                    .ok_or("family is not text")?
                    .to_string(),
                tier: challenge["tier"]
                    .as_u64()
                    .and_then(|tier| u32::try_from(tier).ok())
                    .ok_or("tier is not uint32")?,
                outcome,
                replay,
            })
        })
        .collect()
}
