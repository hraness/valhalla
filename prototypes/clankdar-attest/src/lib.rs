//! Sealed-seed capability attestation — independent Rust implementation of
//! `clankdar-attest-v1`.
//!
//! A verifier issues a challenge whose generator seed is committed but
//! unrevealed: the puzzle instance has never existed publicly, so it cannot be
//! pre-solved or looked up. On a response the verifier rescores
//! deterministically and signs a receipt that reveals the seed — afterward
//! anyone regenerates the instance through the canonical Clankdar generator
//! oracle, rescores the response, and checks the signature without trusting
//! the verifier beyond the episode it signed. The signature covers the
//! payload bytes verbatim, so checkers never re-serialize JSON.
//!
//! Scope: a receipt attests that one signed response satisfied one challenge
//! inside one time window. It is **not** a liveness credential, does not prove
//! a model (or AI) produced the response, grants no authority, and provides no
//! durable replay protection — consumers should issue fresh challenges.
//!
//! Instance generation stays with the canonical TypeScript suite; this crate
//! calls `bench/instance.ts` (the generator oracle) for `issue`, `verify`,
//! and deep checks. The offline [`check_receipt`] path needs no oracle: it
//! verifies the signature, the seed commitment, timing, and rescores the
//! recorded answer pair.

mod scorer;

pub use scorer::{
    answer_format, canonical_answer, score_answer, AnswerFormat, Score, MAX_ANSWER_LENGTH,
    SCORER_VERSION,
};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

/// Wire protocol identifier.
pub const ATTEST_PROTOCOL: &str = "clankdar-attest-v1";
const COMMIT_DOMAIN: &str = "clankdar/attest-seed/v1";

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
    VerifyingKey::from_bytes(&bytes)
        .map_err(|_| AttestError::Malformed("invalid Ed25519 public key".to_string()))
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
/// answer agreement so a verifier cannot sign a fabricated instance.
pub fn verify_response(
    ticket: &Ticket,
    response: &str,
    instance: &GeneratedInstance,
    key: &SigningKey,
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
    let scored = score_answer(&instance.answer, response, format);
    let body = ReceiptBody {
        kind: "receipt".to_string(),
        challenge: challenge.clone(),
        seed: ticket.seed,
        expected: ticket.expected.clone(),
        response: response.to_string(),
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
    /// Why the check failed when `ok` is false.
    pub reason: Option<String>,
}

impl CheckResult {
    fn ok(verdict: bool) -> Self {
        Self {
            ok: true,
            verdict: Some(verdict),
            reason: None,
        }
    }

    fn fail(reason: impl Into<String>) -> Self {
        Self {
            ok: false,
            verdict: None,
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
/// regenerates the instance — see [`check_receipt_deep`].
pub fn check_receipt(receipt: &Receipt) -> CheckResult {
    check_receipt_with(
        receipt,
        |_, _, _, _| Err("deep check skipped".to_string()),
        false,
    )
}

/// Full replay including regeneration through the generator oracle: the
/// recorded prompt and expected answer must reproduce exactly.
pub fn check_receipt_deep(
    receipt: &Receipt,
    oracle: impl Fn(&str, &str, u32, u64) -> Result<GeneratedInstance, String>,
) -> CheckResult {
    check_receipt_with(receipt, oracle, true)
}

fn check_receipt_with(
    receipt: &Receipt,
    oracle: impl Fn(&str, &str, u32, u64) -> Result<GeneratedInstance, String>,
    deep: bool,
) -> CheckResult {
    if receipt.protocol != ATTEST_PROTOCOL {
        return malformed("not an attestation receipt");
    }
    let body: ReceiptBody = match serde_json::from_str(&receipt.payload) {
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
    if key.verify(receipt.payload.as_bytes(), &signature).is_err() {
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
    if score_answer(&body.expected, &body.response, format).pass != body.verdict.pass {
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
    if deep {
        let instance = match oracle(
            &challenge.suite_version,
            &challenge.family,
            challenge.tier,
            body.seed,
        ) {
            Ok(instance) => instance,
            Err(e) => return CheckResult::fail(format!("instance does not regenerate: {e}")),
        };
        if instance.prompt != challenge.prompt {
            return malformed("recorded prompt disagrees with regeneration");
        }
        if canonical_answer(&instance.answer, format) != Some(body.expected.clone()) {
            return malformed("recorded answer disagrees with regeneration");
        }
    }
    CheckResult::ok(body.verdict.pass)
}
