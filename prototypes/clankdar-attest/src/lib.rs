//! Sealed-seed capability attestation — independent Rust implementation of
//! `clankdar-attest-v1`.
//!
//! A verifier issues a challenge whose generator seed is committed but
//! unrevealed. This does not prove the instance is novel or prevent solving
//! with code, precomputation, or delegation. On a response the verifier rescores
//! deterministically and signs a receipt that reveals the seed — afterward
//! anyone regenerates the instance through the canonical Clankdar generator
//! oracle, rescores the response, and checks the signature without trusting
//! the verifier beyond the episode it signed. The signature covers the
//! payload bytes verbatim, so checkers never re-serialize JSON.
//!
//! Scope: an issuer signs submitted-answer evidence under its recorded
//! time window. A `subjectProof` proves key possession for a session/challenge
//! transcript; it does not sign the answer, issuer, policy, context, or receipt.
//! Exact-artifact endorsement is a separate signature. No layer proves who
//! solved the puzzle, model identity, liveness, or authority. Consumers must
//! pin their expected issuer, policy, scope and freshness and retain replay state.
//!
//! This verifier deliberately hardens the upstream-compatible signature subset:
//! weak Ed25519 public keys are rejected and every signature uses strict
//! verification. Ordinary key generation and signed transcript formats are unchanged.
//!
//! Instance generation stays with the canonical TypeScript suite; this crate
//! calls `bench/instance.ts` (the generator oracle) for `issue`, `verify`,
//! and deep checks. The offline [`check_receipt`] path needs no oracle: it
//! verifies the signature, the seed commitment, timing, and rescores the
//! recorded answer pair.
//!
//! On top of the attestation layer sits `clankdar-gate-v1` admission
//! sessions: a [`GatePolicy`] bounds the suite cells, challenge count, pass
//! floor, and deadline; the issuer signs one [`Admission`] binding the
//! complete challenge list, the minted receipts, and the verdict.
//! [`check_admission`] independently replays an admission — envelope and
//! payload shape, per-challenge session binding and cell coverage, the
//! payload signature, every embedded receipt through the deep check,
//! canonical challenge equality, one subject key across proofed receipts,
//! and verdict arithmetic — trusting nothing beyond the recorded episode. An
//! admission attests K passing responses under one policy in one window;
//! like a receipt it is never identity, liveness, or authority.
//!
//! `clankdar-tlog-v1` completes the stack: a derived, hash-chained,
//! issuer-signed transparency log over the gate ledger. [`check_log`]
//! replays every `entryHash` and `prev` link and enforces ledger semantics
//! on entry order; [`prove_session`] reports session/decision inclusion
//! indexes under the signed head; [`check_logged_admission`] is the
//! portable-badge test — the admission must verify on its own AND trace to
//! a logged, decided session. The log binds the issuer's history under its
//! own key only: it prevents neither self-minting nor forking.
//!
//! The `rooms` module dogfoods the gate layer the way a valhalla rooms
//! node would: [`issue_room_session`] mints a room-admission session as
//! the room-side issuer, [`submit_room_session`] consumes responses into
//! the signed admission, and [`decide_room_admission`] runs the room's
//! admission decision — replaying the signed admission and pinning it to
//! the room's published floor and verifier key.
//!
//! `clankdar-holdout-v1` adds issuer-private pools whose secret labels
//! re-parameterize published cells (`h:family:tN`): held-out challenges
//! carry `heldout: {poolKey}` and replay only for a checker holding the
//! committed pool — everyone else verifies the envelope while the score
//! stays issuer-claimed (`replayable: false`).
//!
//! `clankdar-badge-v1` completes the stack: subject-signed portable badges
//! aggregating subject-bound admissions across issuers. [`check_badge`]
//! replays every carried admission through the full gate check, requires
//! subject binding (every proof-carrying receipt uses the badge's
//! `subjectKey`, and at least one receipt must carry a proof), replays
//! optional tlog inclusion proofs against their own logs, and verifies the
//! subject's signature over the payload bytes. Disclosed holdout pools —
//! the set may mix issuers — are indexed by `poolKey`; undisclosed scores
//! stay valid but sum into `unreplayed`. A badge proves the subject key
//! accumulated these admissions — never that the holder solved them, and
//! never identity, liveness, or authority.

mod badge;
mod gate;
mod holdout;
mod rooms;
mod scorer;
mod tlog;

pub use badge::{
    check_badge, pack_badge, Badge, BadgeBody, BadgeCheck, BadgeProof, PackBadgeOptions,
    BADGE_PROTOCOL, MAX_BADGE_ADMISSIONS,
};
pub use gate::{
    check_admission, check_admission_with_pool, issue_session, submit_session, suite_version,
    Admission, AdmissionBody, AdmissionCheck, AdmissionVerdict, GatePolicy, GateSession,
    IssueSessionOptions, SubmitSessionOptions, AGENT_SUITE_VERSION, ALGAL_SUITE_VERSION,
    FRONTIER_SUITE_VERSION, GATE_PROTOCOL, MAX_POLICY_CELLS, MAX_POLICY_CHALLENGES,
    MAX_POLICY_TTL_SECONDS, MIN_POLICY_TTL_SECONDS, V2_SUITE_VERSION,
};
pub use holdout::{
    holdout_cell, holdout_instance, instance_for, mix_seed, pool_key_of, HoldoutCell, HoldoutPool,
    HOLDOUT_PROTOCOL, MAX_POOL_CELLS,
};
pub use rooms::{
    decide_room_admission, issue_room_session, submit_room_session, RoomDecision, RoomFloor,
    RoomSession, RoomSessionOptions, RoomSubmission,
};
pub use scorer::{
    answer_format, canonical_answer, score_answer, AnswerFormat, Score, MAX_ANSWER_LENGTH,
    SCORER_VERSION,
};
pub use tlog::{
    check_log, check_logged_admission, check_logged_admission_with_pool, entries_for, entry_hash,
    prove_session, AdmittedCheck, LogCheck, SessionProof, TlogEntry, TlogHashedEntry, TlogHead,
    TransparencyLog, TLOG_PROTOCOL,
};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

/// Wire protocol identifier.
pub const ATTEST_PROTOCOL: &str = "clankdar-attest-v1";
const COMMIT_DOMAIN: &str = "clankdar/attest-seed/v1";
const SUBJECT_DOMAIN: &str = "clankdar/subject/v1";

/// Minimum challenge lifetime, in seconds.
pub const MIN_TTL_SECONDS: i64 = 10;
/// Maximum challenge lifetime, in seconds.
pub const MAX_TTL_SECONDS: i64 = 86_400;
/// Maximum `context` length in bytes.
pub const MAX_CONTEXT_LEN: usize = 256;

/// A sealed challenge: the prompt is public, the seed is committed but
/// hidden until the receipt reveals it.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Challenge {
    /// Protocol identifier.
    pub protocol: String,
    /// Object kind (`"challenge"`).
    pub kind: String,
    /// Unique challenge identifier (`att_` + base64url).
    pub challenge_id: String,
    /// Generator pool version that produced the instance.
    pub suite_version: String,
    /// Puzzle family name.
    pub family: String,
    /// Difficulty tier inside the family.
    pub tier: u32,
    /// The generated prompt shown to the candidate.
    pub prompt: String,
    /// SHA-256 commitment over the sealed seed and challenge fields.
    pub seed_commit: String,
    /// Fresh challenge nonce.
    pub nonce: String,
    /// RFC 3339 expiry instant.
    pub expires_at: String,
    /// Optional application scope binding.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<String>,
    /// Optional relying-party subject claim (e.g. an agent or session key id).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    /// Gate session this challenge was issued under (clankdar-gate-v1).
    ///
    /// Challenge serde intentionally tolerates unknown members: the protocol
    /// permits optional and future fields, so no `deny_unknown_fields` here.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// Held-out cell marker (clankdar-holdout-v1): `{poolKey}` commits the
    /// pool the instance replays under. Kept as a raw member so a malformed
    /// marker still parses as a challenge and fails its own check —
    /// `heldout !== undefined` selects the held-out path in the TypeScript
    /// checker, and member *presence* (not shape) is what selects it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub heldout: Option<serde_json::Value>,
    /// Verifier key identity.
    pub verifier: VerifierRef,
}

/// The verifier's public identity recorded on a challenge.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifierRef {
    /// First 16 hex chars of SHA-256 over the raw public key.
    pub key_id: String,
    /// Base64url (no padding) raw Ed25519 public key.
    pub public_key: String,
}

/// Verifier-side ticket pairing the sealed seed with the challenge.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Ticket {
    /// The challenge that was issued.
    pub challenge: Challenge,
    /// Sealed seed; revealed only inside a signed receipt.
    pub seed: u64,
    /// Canonical expected answer.
    pub expected: String,
}

/// A respondent's optional key proof: `publicKey` is a base64url Ed25519 JWK
/// `x` member (the same encoding as verifier keys) and `signature` is a
/// base64url Ed25519 signature over the challenge's subject transcript. It
/// proves key possession for the session/challenge transcript only. It does
/// not sign the exact response, issuer, policy, or receipt. Exact-artifact
/// endorsement needs a separate subject-signed envelope. Neither establishes
/// who solved the puzzle, a model identity, a person, or authority.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubjectProof {
    /// Respondent Ed25519 public key, base64url (no padding).
    pub public_key: String,
    /// Base64url Ed25519 signature over the subject transcript.
    pub signature: String,
}

/// The signed body serialized inside [`Receipt::payload`].
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReceiptBody {
    /// Object kind (`"receipt"`).
    pub kind: String,
    /// The challenge that was answered.
    pub challenge: Challenge,
    /// The revealed seed.
    pub seed: u64,
    /// Canonical expected answer.
    pub expected: String,
    /// The candidate's raw response.
    pub response: String,
    /// Optional respondent key proof, embedded inside the signed payload.
    /// Kept as a raw member so a malformed proof still parses as a receipt
    /// body and then fails the proof check itself — mirroring the TypeScript
    /// checker, which reads `subjectProof` off the parsed payload.
    #[serde(rename = "subjectProof", skip_serializing_if = "Option::is_none")]
    pub subject_proof: Option<serde_json::Value>,
    /// Scoring outcome.
    pub verdict: Verdict,
}

/// The scored outcome recorded in a receipt.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Verdict {
    /// Whether the response canonically matched the expected answer.
    pub pass: bool,
    /// The declared answer format used for scoring.
    pub format: String,
    /// RFC 3339 instant the verifier scored the response.
    pub answered_at: String,
}

/// A signed receipt: `payload` is canonical JSON signed verbatim.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Receipt {
    /// Protocol identifier.
    pub protocol: String,
    /// Canonical JSON of the [`ReceiptBody`], signed verbatim.
    pub payload: String,
    /// Base64url Ed25519 signature over `payload` bytes.
    pub signature: String,
}

/// A regenerated instance returned by the generator oracle. The identity
/// fields are echoed back so the protocol can bind the oracle output to the
/// requested cell and seed.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GeneratedInstance {
    /// The generator pool version that produced the instance.
    pub suite_version: String,
    /// Puzzle family name.
    pub family: String,
    /// Difficulty tier.
    pub tier: u32,
    /// The seed the instance was generated for.
    pub seed: u64,
    /// The canonical prompt text.
    pub prompt: String,
    /// The canonical expected answer (pre-canonicalization).
    pub answer: String,
}

/// A verifier Ed25519 keypair as an OKP JWK (`{kty, crv, x, d}`).
#[derive(Clone, Serialize, Deserialize)]
pub struct VerifierJwk {
    /// Key type (`"OKP"`).
    pub kty: String,
    /// Curve (`"Ed25519"`).
    pub crv: String,
    /// Base64url public key.
    pub x: String,
    /// Base64url private seed.
    pub d: String,
}

/// Failure reasons for issue/verify/check.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AttestError {
    /// The cell, seed, TTL, or context is out of bounds.
    InvalidInput(String),
    /// The challenge or ticket is malformed.
    Malformed(String),
    /// The challenge has expired.
    Expired,
    /// A signature, commitment, or regeneration check failed.
    Mismatch(String),
    /// The response is not in the declared answer format.
    BadFormat(String),
}

impl std::fmt::Display for AttestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidInput(m) | Self::Malformed(m) | Self::Mismatch(m) | Self::BadFormat(m) => {
                f.write_str(m)
            }
            Self::Expired => f.write_str("challenge expired"),
        }
    }
}

impl std::error::Error for AttestError {}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for b in digest {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

fn b64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn b64url_decode(value: &str) -> Result<Vec<u8>, AttestError> {
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| AttestError::Malformed("invalid base64url".to_string()))
}

/// `keyIdOf`: first 16 hex chars of SHA-256 over the raw public key.
pub fn key_id_of(public_key_b64: &str) -> Result<String, AttestError> {
    let bytes = b64url_decode(public_key_b64)?;
    Ok(sha256_hex(&bytes)[..16].to_string())
}

/// `seedCommit`: SHA-256 over the fixed-field NUL-joined record. Language
/// trivial so any checker can recompute it.
pub fn seed_commit(suite_version: &str, family: &str, tier: u32, nonce: &str, seed: u64) -> String {
    let joined = format!("{COMMIT_DOMAIN}\0{suite_version}\0{family}\0{tier}\0{nonce}\0{seed}");
    sha256_hex(joined.as_bytes())
}

/// Deterministic JSON used for signing: object keys sorted recursively,
/// compact separators, matching the TypeScript `canonical()` helper.
pub fn canonical_json(value: &serde_json::Value) -> String {
    let mut out = String::new();
    write_canonical(value, &mut out);
    out
}

fn write_canonical(value: &serde_json::Value, out: &mut String) {
    match value {
        serde_json::Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push('{');
            for (i, key) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(key).unwrap_or_default());
                out.push(':');
                write_canonical(&map[*key], out);
            }
            out.push('}');
        }
        serde_json::Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(item, out);
            }
            out.push(']');
        }
        other => out.push_str(&serde_json::to_string(other).unwrap_or_default()),
    }
}

/// Generate a fresh verifier keypair as an OKP JWK.
pub fn generate_verifier() -> VerifierJwk {
    let mut rng = rand_core::OsRng;
    let signing = SigningKey::generate(&mut rng);
    let verifying = signing.verifying_key();
    VerifierJwk {
        kty: "OKP".to_string(),
        crv: "Ed25519".to_string(),
        x: b64url(&verifying.to_bytes()),
        d: b64url(&signing.to_bytes()),
    }
}

/// Load a signing key from a JWK.
pub fn signing_key(jwk: &VerifierJwk) -> Result<SigningKey, AttestError> {
    if jwk.kty != "OKP" || jwk.crv != "Ed25519" {
        return Err(AttestError::Malformed(
            "verifier key must be an Ed25519 OKP JWK".to_string(),
        ));
    }
    let seed = b64url_decode(&jwk.d)?;
    let seed: [u8; 32] = seed
        .try_into()
        .map_err(|_| AttestError::Malformed("Ed25519 seed must be 32 bytes".to_string()))?;
    let key = SigningKey::from_bytes(&seed);
    if b64url(&key.verifying_key().to_bytes()) != jwk.x {
        return Err(AttestError::Mismatch(
            "JWK public member does not match the private seed".to_string(),
        ));
    }
    Ok(key)
}

/// Load a verifying key from a base64url raw public key.
fn verifying_key(public_key_b64: &str) -> Result<VerifyingKey, AttestError> {
    let bytes = b64url_decode(public_key_b64)?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| AttestError::Malformed("Ed25519 public key must be 32 bytes".to_string()))?;
    let key = VerifyingKey::from_bytes(&bytes)
        .map_err(|_| AttestError::Malformed("invalid Ed25519 public key".to_string()))?;
    // A small-order key can admit fabricated signatures without possession of
    // a secret. This deliberately hardens the upstream compatibility subset.
    if key.is_weak() {
        return Err(AttestError::Malformed(
            "weak Ed25519 public key".to_string(),
        ));
    }
    Ok(key)
}

/// `subjectTranscript`: the domain-separated transcript a subject proof
/// signs. Session-scoped when the challenge carries `sessionId` — one proof
/// then covers every challenge minted under that gate session. Standalone
/// challenges bind the proof to the single `challengeId` + `nonce` instead.
pub fn subject_transcript(challenge: &Challenge, public_key: &str) -> String {
    match &challenge.session_id {
        Some(session_id) => {
            canonical_json(&serde_json::json!([SUBJECT_DOMAIN, session_id, public_key]))
        }
        None => canonical_json(&serde_json::json!([
            SUBJECT_DOMAIN,
            challenge.challenge_id,
            challenge.nonce,
            public_key
        ])),
    }
}

/// Transcript over the raw challenge member, used by the check path: a
/// present `sessionId` — even `null` — selects the session scope, exactly
/// matching `challenge.sessionId !== undefined` in TypeScript. Missing
/// `challengeId`/`nonce` members serialize as `null`, as `canonical` does
/// with `undefined` array members.
fn subject_transcript_of(challenge: Option<&serde_json::Value>, public_key: &str) -> String {
    let member = |key: &str| challenge.and_then(|c| c.get(key)).cloned();
    match member("sessionId") {
        Some(session_id) => {
            canonical_json(&serde_json::json!([SUBJECT_DOMAIN, session_id, public_key]))
        }
        None => canonical_json(&serde_json::json!([
            SUBJECT_DOMAIN,
            member("challengeId").unwrap_or(serde_json::Value::Null),
            member("nonce").unwrap_or(serde_json::Value::Null),
            public_key,
        ])),
    }
}

/// Ed25519 verification over a subject transcript — never throws, mirroring
/// `checkSubjectProof`'s try/catch: bad key material or a bad signature is a
/// failed check, not a malformed receipt.
fn subject_signature_verifies(transcript: &str, proof: &SubjectProof) -> bool {
    let Ok(key) = verifying_key(&proof.public_key) else {
        return false;
    };
    let Ok(bytes) = b64url_decode(&proof.signature) else {
        return false;
    };
    let Ok(signature) = Signature::from_slice(&bytes) else {
        return false;
    };
    key.verify_strict(transcript.as_bytes(), &signature).is_ok()
}

/// `subjectProofFor`: mint a subject proof for a challenge with a respondent
/// Ed25519 JWK (the same key shape as verifier keys).
pub fn subject_proof_for(
    challenge: &Challenge,
    jwk: &VerifierJwk,
) -> Result<SubjectProof, AttestError> {
    let key = signing_key(jwk)?;
    let public_key = b64url(&key.verifying_key().to_bytes());
    let signature = key.sign(subject_transcript(challenge, &public_key).as_bytes());
    Ok(SubjectProof {
        public_key,
        signature: b64url(&signature.to_bytes()),
    })
}

/// `checkSubjectProof`: independently verify a subject proof against the
/// challenge's transcript.
pub fn check_subject_proof(challenge: &Challenge, proof: &SubjectProof) -> bool {
    subject_signature_verifies(&subject_transcript(challenge, &proof.public_key), proof)
}

fn random_b64url(len: usize) -> String {
    let mut bytes = vec![0u8; len];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut bytes);
    b64url(&bytes)
}

fn parse_time(value: &str) -> Result<OffsetDateTime, AttestError> {
    OffsetDateTime::parse(value, &Rfc3339)
        .map_err(|_| AttestError::Malformed(format!("not an RFC 3339 timestamp: {value}")))
}

/// `^gs_[A-Za-z0-9_-]{12}$` — the gate session id shape.
fn is_session_id(value: &str) -> bool {
    value.len() == 15
        && value.starts_with("gs_")
        && value[3..]
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// `/^[0-9a-f]{64}$/` — the `heldout.poolKey` marker shape. A marker that
/// is not an object carrying a 64-hex string is malformed — including
/// `heldout: null`, where the TypeScript checker throws on `null.poolKey`;
/// reporting it malformed is the graceful equivalent.
fn heldout_pool_key(marker: &serde_json::Value) -> Option<&str> {
    match marker.get("poolKey").and_then(serde_json::Value::as_str) {
        Some(key)
            if key.len() == 64
                && key
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) =>
        {
            Some(key)
        }
        _ => None,
    }
}

/// Draw a fresh uint32 seed. Callers draw first, then ask the generator
/// oracle for that seed's instance, then call [`issue_challenge`].
pub fn draw_seed() -> u64 {
    let mut bytes = [0u8; 4];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut bytes);
    u32::from_be_bytes(bytes) as u64
}

/// Options for [`issue_challenge`].
pub struct IssueOptions<'a> {
    /// Puzzle family name.
    pub family: &'a str,
    /// Difficulty tier.
    pub tier: u32,
    /// Challenge lifetime in seconds (default 300).
    pub ttl_seconds: Option<i64>,
    /// Optional application scope binding.
    pub context: Option<String>,
    /// Optional relying-party subject claim.
    pub subject: Option<String>,
    /// Optional gate session id binding (clankdar-gate-v1).
    pub session_id: Option<String>,
    /// Mint the cell from this holdout pool instead of the published
    /// stream (clankdar-holdout-v1). The pool must cover the requested
    /// `family:tier` cell and match the instance's suite; the caller
    /// supplies an instance regenerated through [`crate::holdout_instance`].
    pub holdout_pool: Option<&'a HoldoutPool>,
    /// Issuance instant; `None` uses the wall clock.
    pub now: Option<OffsetDateTime>,
}

/// Mint a sealed challenge and the verifier-side ticket. `instance` must be
/// the canonical generator output for `(family, tier, seed)` — the oracle
/// echoes its resolved `suite_version`, which is what the challenge records,
/// and the echoed identity fields must match the request exactly.
pub fn issue_challenge(
    opts: &IssueOptions<'_>,
    seed: u64,
    instance: &GeneratedInstance,
    key: &SigningKey,
) -> Result<(Challenge, Ticket), AttestError> {
    if seed > u32::MAX as u64
        || instance.seed != seed
        || instance.family != opts.family
        || instance.tier != opts.tier
    {
        return Err(AttestError::Mismatch(
            "oracle instance does not match the requested cell and seed".to_string(),
        ));
    }
    // A holdout pool must name the same suite the instance regenerated
    // under and carry the requested cell — mirroring `issueChallenge`,
    // which rejects a foreign suite or a missing cell before minting.
    if let Some(pool) = opts.holdout_pool {
        if suite_version(&pool.suite) != instance.suite_version {
            return Err(AttestError::InvalidInput(
                "holdout pool is for a different suite".to_string(),
            ));
        }
        if holdout_cell(pool, opts.family, opts.tier as u64).is_none() {
            return Err(AttestError::InvalidInput(format!(
                "cell is not in the holdout pool: {}:t{}",
                opts.family, opts.tier
            )));
        }
    }
    let ttl = opts.ttl_seconds.unwrap_or(300);
    if !(MIN_TTL_SECONDS..=MAX_TTL_SECONDS).contains(&ttl) {
        return Err(AttestError::InvalidInput(
            "ttl must be 10..86400 seconds".to_string(),
        ));
    }
    if let Some(context) = &opts.context {
        if context.len() > MAX_CONTEXT_LEN {
            return Err(AttestError::InvalidInput(
                "context must be at most 256 chars".to_string(),
            ));
        }
    }
    if let Some(subject) = &opts.subject {
        if subject.is_empty() || subject.len() > MAX_CONTEXT_LEN {
            return Err(AttestError::InvalidInput(
                "subject must be a nonempty string up to 256 chars".to_string(),
            ));
        }
    }
    if let Some(session_id) = &opts.session_id {
        if !is_session_id(session_id) {
            return Err(AttestError::InvalidInput(
                "sessionId must be a gate session id".to_string(),
            ));
        }
    }
    let now = opts.now.unwrap_or_else(OffsetDateTime::now_utc);
    let expires_at = (now + time::Duration::seconds(ttl))
        .format(&Rfc3339)
        .map_err(|e| AttestError::Malformed(e.to_string()))?;
    let nonce = random_b64url(12);
    let public_key = b64url(&key.verifying_key().to_bytes());
    let challenge = Challenge {
        protocol: ATTEST_PROTOCOL.to_string(),
        kind: "challenge".to_string(),
        challenge_id: format!("att_{}", random_b64url(9)),
        suite_version: instance.suite_version.clone(),
        family: instance.family.clone(),
        tier: opts.tier,
        prompt: instance.prompt.clone(),
        seed_commit: seed_commit(
            &instance.suite_version,
            opts.family,
            opts.tier,
            &nonce,
            seed,
        ),
        nonce,
        expires_at,
        context: opts.context.clone(),
        subject: opts.subject.clone(),
        session_id: opts.session_id.clone(),
        heldout: opts
            .holdout_pool
            .map(|pool| serde_json::json!({"poolKey": pool.pool_key})),
        verifier: VerifierRef {
            key_id: key_id_of(&public_key)?,
            public_key,
        },
    };
    let expected = canonical_answer(&instance.answer, answer_format(opts.family))
        .ok_or_else(|| AttestError::Malformed("generated answer is not canonical".to_string()))?;
    Ok((
        challenge.clone(),
        Ticket {
            challenge,
            seed,
            expected,
        },
    ))
}

/// Rescore the response and sign a seed-revealing receipt. `instance` must be
/// regenerated for the ticket's seed; the function checks prompt equality and
/// answer agreement so a verifier cannot sign a fabricated instance. An
/// optional `subject_proof` — verified against the challenge transcript
/// before minting — embeds inside the signed payload.
pub fn verify_response(
    ticket: &Ticket,
    response: &str,
    instance: &GeneratedInstance,
    key: &SigningKey,
    subject_proof: Option<&SubjectProof>,
    now: Option<OffsetDateTime>,
) -> Result<Receipt, AttestError> {
    let challenge = &ticket.challenge;
    if challenge.protocol != ATTEST_PROTOCOL || challenge.kind != "challenge" {
        return Err(AttestError::Malformed(
            "not an attestation challenge".to_string(),
        ));
    }
    if challenge.seed_commit
        != seed_commit(
            &challenge.suite_version,
            &challenge.family,
            challenge.tier,
            &challenge.nonce,
            ticket.seed,
        )
    {
        return Err(AttestError::Mismatch(
            "ticket seed does not match the committed challenge".to_string(),
        ));
    }
    let now = now.unwrap_or_else(OffsetDateTime::now_utc);
    if now > parse_time(&challenge.expires_at)? {
        return Err(AttestError::Expired);
    }
    if response.len() > MAX_ANSWER_LENGTH {
        return Err(AttestError::InvalidInput(
            "response missing or oversized".to_string(),
        ));
    }
    if instance.suite_version != challenge.suite_version
        || instance.family != challenge.family
        || instance.tier != challenge.tier
        || instance.seed != ticket.seed
        || instance.prompt != challenge.prompt
    {
        return Err(AttestError::Mismatch(
            "challenge does not regenerate from the committed seed".to_string(),
        ));
    }
    let format = answer_format(&challenge.family);
    if canonical_answer(&instance.answer, format) != Some(ticket.expected.clone())
        || canonical_answer(&ticket.expected, format) != Some(ticket.expected.clone())
    {
        return Err(AttestError::Mismatch(
            "ticket answer does not match the regenerated instance".to_string(),
        ));
    }
    if let Some(proof) = subject_proof {
        if !check_subject_proof(challenge, proof) {
            return Err(AttestError::Mismatch(
                "subject proof does not verify for this challenge".to_string(),
            ));
        }
    }
    let scored = score_answer(&instance.answer, response, format);
    let body = ReceiptBody {
        kind: "receipt".to_string(),
        challenge: challenge.clone(),
        seed: ticket.seed,
        expected: ticket.expected.clone(),
        response: response.to_string(),
        subject_proof: subject_proof
            .map(serde_json::to_value)
            .transpose()
            .map_err(|e| AttestError::Malformed(e.to_string()))?,
        verdict: Verdict {
            pass: scored.pass,
            format: format.as_str().to_string(),
            answered_at: now
                .format(&Rfc3339)
                .map_err(|e| AttestError::Malformed(e.to_string()))?,
        },
    };
    let payload = canonical_json(
        &serde_json::to_value(&body).map_err(|e| AttestError::Malformed(e.to_string()))?,
    );
    let signature = b64url(&key.sign(payload.as_bytes()).to_bytes());
    Ok(Receipt {
        protocol: ATTEST_PROTOCOL.to_string(),
        payload,
        signature,
    })
}

/// Outcome of an independent receipt check.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CheckResult {
    /// Every offline verification step passed.
    pub ok: bool,
    /// The recorded verdict when `ok` holds.
    pub verdict: Option<bool>,
    /// `false` when a held-out cell could not be replayed without its
    /// pool — signature, commitment, timing, and answer canonicality still
    /// verified, but the score stays issuer-claimed. Absent for every
    /// fully replayed (or never replayable) receipt, mirroring the
    /// TypeScript `replayable` member.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replayable: Option<bool>,
    /// Why the check failed when `ok` is false.
    pub reason: Option<String>,
}

impl CheckResult {
    fn ok(verdict: bool, replayable: Option<bool>) -> Self {
        Self {
            ok: true,
            verdict: Some(verdict),
            replayable,
            reason: None,
        }
    }

    fn fail(reason: impl Into<String>) -> Self {
        Self {
            ok: false,
            verdict: None,
            replayable: None,
            reason: Some(reason.into()),
        }
    }
}

fn malformed(reason: &str) -> CheckResult {
    CheckResult::fail(reason)
}

/// Independently replay a receipt without any generator access: signature over
/// the verbatim payload, key identity, seed commitment, response format,
/// verdict rescore, and answer-before-expiry. Deep verification additionally
/// regenerates the instance — see [`check_receipt_deep`]. A `heldout`-marked
/// challenge cannot regenerate without its pool, so it reports
/// `replayable: false` here exactly as `checkReceipt(receipt)` does.
pub fn check_receipt(receipt: &Receipt) -> CheckResult {
    check_receipt_impl(
        receipt,
        None,
        |_, _, _, _| Err("deep check skipped".to_string()),
        false,
    )
}

/// Full replay including regeneration through the generator oracle: the
/// recorded prompt and expected answer must reproduce exactly. A `heldout`
/// challenge without a supplied pool skips regeneration and reports
/// `replayable: false` — the oracle is never consulted for it.
pub fn check_receipt_deep(
    receipt: &Receipt,
    oracle: impl Fn(&str, &str, u32, u64) -> Result<GeneratedInstance, String>,
) -> CheckResult {
    check_receipt_impl(receipt, None, oracle, true)
}

/// `checkReceipt(receipt, {pool})` — the deep check with an optional
/// holdout pool. A `heldout` marker whose `poolKey` names the supplied
/// pool regenerates through the pool's secret label; a mismatched or
/// absent pool leaves the score issuer-claimed (`replayable: false`), and
/// a matching pool that lacks the named cell proves fabrication — a hard
/// failure, not merely an unreplayable one.
pub fn check_receipt_with_pool(
    receipt: &Receipt,
    pool: Option<&HoldoutPool>,
    oracle: impl Fn(&str, &str, u32, u64) -> Result<GeneratedInstance, String>,
) -> CheckResult {
    check_receipt_impl(receipt, pool, oracle, true)
}

fn check_receipt_impl(
    receipt: &Receipt,
    pool: Option<&HoldoutPool>,
    oracle: impl Fn(&str, &str, u32, u64) -> Result<GeneratedInstance, String>,
    deep: bool,
) -> CheckResult {
    if receipt.protocol != ATTEST_PROTOCOL {
        return malformed("not an attestation receipt");
    }
    // The raw payload is kept alongside the typed body: `subjectProof` is
    // checked by member presence (`!== undefined`), which the typed body
    // cannot express.
    let raw: serde_json::Value = match serde_json::from_str(&receipt.payload) {
        Ok(raw) => raw,
        Err(_) => return malformed("payload is not a receipt body"),
    };
    let body: ReceiptBody = match serde_json::from_value(raw.clone()) {
        Ok(body) => body,
        Err(_) => return malformed("payload is not a receipt body"),
    };
    if body.kind != "receipt"
        || body.challenge.protocol != ATTEST_PROTOCOL
        || body.challenge.kind != "challenge"
    {
        return malformed("malformed receipt payload");
    }
    let challenge = &body.challenge;
    let key = match verifying_key(&challenge.verifier.public_key) {
        Ok(key) => key,
        Err(e) => return malformed(&e.to_string()),
    };
    match key_id_of(&challenge.verifier.public_key) {
        Ok(id) if id == challenge.verifier.key_id => {}
        _ => return malformed("verifier keyId does not match the public key"),
    }
    let signature = match b64url_decode(&receipt.signature) {
        Ok(bytes) => match Signature::from_slice(&bytes) {
            Ok(sig) => sig,
            Err(_) => return malformed("signature is not 64 bytes"),
        },
        Err(e) => return malformed(&e.to_string()),
    };
    if key
        .verify_strict(receipt.payload.as_bytes(), &signature)
        .is_err()
    {
        return malformed("signature does not verify");
    }
    if body.seed > u32::MAX as u64 {
        return malformed("revealed seed is not a uint32");
    }
    if challenge.seed_commit
        != seed_commit(
            &challenge.suite_version,
            &challenge.family,
            challenge.tier,
            &challenge.nonce,
            body.seed,
        )
    {
        return malformed("revealed seed does not match the committed challenge");
    }
    // Instance resolution, mirroring the TypeScript checker's held-out
    // branch in place (marker, pool, and cell checks precede the answer
    // format checks). Member presence selects the held-out path — a
    // present `heldout` of any shape must carry `{poolKey: <64 hex>}`.
    // Without a matching pool the instance stays unresolved: the envelope
    // still verifies and the score is issuer-claimed (`replayable:false`).
    let mut instance: Option<GeneratedInstance> = None;
    let heldout = raw.get("challenge").and_then(|c| c.get("heldout"));
    if let Some(marker) = heldout {
        let Some(pool_key) = heldout_pool_key(marker) else {
            return malformed("malformed heldout marker");
        };
        if let Some(pool) = pool.filter(|p| p.pool_key == pool_key) {
            let Some(cell) = holdout_cell(pool, &challenge.family, challenge.tier as u64) else {
                return malformed("held-out cell is not in the committed pool");
            };
            if deep {
                instance = Some(match holdout_instance(pool, cell, body.seed, &oracle) {
                    Ok(instance) => instance,
                    Err(e) => {
                        return CheckResult::fail(format!(
                            "held-out instance does not regenerate: {e}"
                        ))
                    }
                });
            }
        }
    } else if deep {
        instance = Some(
            match oracle(
                &challenge.suite_version,
                &challenge.family,
                challenge.tier,
                body.seed,
            ) {
                Ok(instance) => instance,
                Err(e) => return CheckResult::fail(format!("instance does not regenerate: {e}")),
            },
        );
    }
    let format = match AnswerFormat::parse(&body.verdict.format) {
        Some(format) => format,
        None => return malformed("unknown verdict answer format"),
    };
    if format != answer_format(&challenge.family) {
        return malformed("verdict format does not match the family contract");
    }
    if canonical_answer(&body.response, format).is_none() {
        return malformed("response is not in the declared answer format");
    }
    if canonical_answer(&body.expected, format) != Some(body.expected.clone()) {
        return malformed("recorded answer is not canonical for its format");
    }
    // Prompt equality, answer agreement, and the verdict rescore all run
    // against the regenerated instance — an unresolved held-out cell skips
    // them entirely since its score stays issuer-claimed. For a published
    // receipt checked offline (no oracle), the shallow path still rescores
    // the recorded answer pair.
    if let Some(instance) = &instance {
        if instance.prompt != challenge.prompt {
            return malformed("recorded prompt disagrees with regeneration");
        }
        if canonical_answer(&instance.answer, format) != Some(body.expected.clone()) {
            return malformed("recorded answer disagrees with regeneration");
        }
        if score_answer(&instance.answer, &body.response, format).pass != body.verdict.pass {
            return malformed("verdict does not rescore");
        }
    } else if heldout.is_none()
        && score_answer(&body.expected, &body.response, format).pass != body.verdict.pass
    {
        return malformed("verdict does not rescore");
    }
    let answered = match parse_time(&body.verdict.answered_at) {
        Ok(t) => t,
        Err(e) => return malformed(&e.to_string()),
    };
    let expires = match parse_time(&challenge.expires_at) {
        Ok(t) => t,
        Err(e) => return malformed(&e.to_string()),
    };
    if answered > expires {
        return malformed("answer is later than the challenge expiry");
    }
    // §7 subject binding, checked last as in the TypeScript checker. A
    // present `subjectProof` — even `null` — must carry a verifiable proof:
    // `!== undefined` counts `null` as present, so presence is read off the
    // raw payload, and the transcript scope reads the raw `sessionId` member.
    if let Some(proof_value) = raw.get("subjectProof") {
        let proof: SubjectProof = match serde_json::from_value(proof_value.clone()) {
            Ok(proof) => proof,
            Err(_) => return malformed("malformed subject proof"),
        };
        let transcript = subject_transcript_of(raw.get("challenge"), &proof.public_key);
        if !subject_signature_verifies(&transcript, &proof) {
            return malformed("subject proof does not verify");
        }
    }
    // `...(instance === undefined ? {replayable: false} : {})` — the only
    // unresolved-but-valid case is a held-out cell without its pool.
    CheckResult::ok(
        body.verdict.pass,
        (instance.is_none() && heldout.is_some()).then_some(false),
    )
}

/// Bounded, explicitly partial views of voluntarily shared signed results.
pub mod history;
pub use history::{
    check_history, HistoryBinding, HistoryChallenge, HistoryChallengeOutcome,
    HistoryChallengeReplay, HistoryCoverage, HistoryCursor, HistoryError, HistoryExpectation,
    HistoryOutcome, HistoryPage, HistoryRecord, HistoryRejection, HistoryReplay, HistorySnapshot,
    MAX_HISTORY_ADMISSION_BYTES, MAX_HISTORY_BYTES, MAX_HISTORY_PAGE, MAX_HISTORY_RECORDS,
};
