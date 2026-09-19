//! Rooms admission dogfood — the room-side `clankdar-gate-v1` flow.
//!
//! A valhalla "room" is a consensus group; the product vision is that an
//! agent joining a room presents a clankdar admission proving it passed the
//! room's published capability floor. This module runs that flow the way a
//! rooms node would:
//!
//! 1. The room publishes a [`GatePolicy`] (its floor) and a verifier key.
//!    [`issue_room_session`] mints a room-admission session as the
//!    room-side issuer: `policy.challenges` sealed challenges drawn
//!    uniformly from the policy cells (with replacement) under one fresh
//!    session id and one shared deadline. The [`RoomSession`] is
//!    issuer-private — it carries the seeds; the challenge list is what
//!    the respondent sees.
//! 2. [`submit_room_session`] consumes the respondent's answers into a
//!    signed [`Admission`]: one receipt per answered, format-canonical
//!    challenge, and every minted receipt is replayed through the
//!    independent deep check before the verdict is signed — the issuer
//!    checks its own work rather than trusting it.
//! 3. [`decide_room_admission`] is the room's admission decision: replay
//!    the presented admission through [`check_admission`], pin it to the
//!    room's own [`RoomFloor`], and admit exactly when the signed verdict
//!    verifies as a pass. The decision is a pure function of the signed
//!    artifact — no flag, claim, or issuer say-so enters it.
//!
//! Honest scope: an admission attests that one session produced K passing
//! responses under one policy in one window. It is capability evidence —
//! never identity, liveness, or authority. This module moves the admission
//! decision into Rust; it is not a rooms transport, a policy-publication
//! mechanism, or join authorization.

use std::collections::{BTreeMap, HashMap};

use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::gate::parse_cell;
use crate::{
    answer_format, b64url, canonical_answer, canonical_json, check_admission, check_receipt_deep,
    draw_seed, issue_challenge, parse_time, random_b64url, suite_version, verify_response,
    Admission, AdmissionBody, AdmissionVerdict, AttestError, Challenge, GatePolicy,
    GeneratedInstance, IssueOptions, Receipt, SubjectProof, Ticket, GATE_PROTOCOL,
};

/// Verifier-side room session state: the secret twin of the published
/// challenge list (mirrors `GateSession` in `bench/gate.ts`, member names
/// included, so a serialized session round-trips the TypeScript shape).
/// `tickets` carry the sealed seeds — a persisted session is private
/// issuer state, never a published artifact.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RoomSession {
    /// Protocol identifier (`clankdar-gate-v1`).
    pub protocol: String,
    /// Object kind (`"session"`).
    pub kind: String,
    /// Session identifier (`gs_` + base64url).
    pub session_id: String,
    /// The room floor the session runs under.
    pub policy: GatePolicy,
    /// Respondent claim bound into every challenge and the admission.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    /// Room scope binding (e.g. the room's own id or a join nonce).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<String>,
    /// RFC 3339 issuance instant.
    pub issued_at: String,
    /// Uniform deadline; identical to every challenge's `expiresAt`.
    pub expires_at: String,
    /// Issuer-side tickets pairing each challenge with its seed and
    /// canonical answer.
    pub tickets: Vec<Ticket>,
}

impl RoomSession {
    /// The public challenge list — the half of the session the respondent
    /// is meant to see.
    pub fn challenges(&self) -> Vec<Challenge> {
        self.tickets.iter().map(|t| t.challenge.clone()).collect()
    }
}

/// Options for [`issue_room_session`].
#[derive(Default)]
pub struct RoomSessionOptions<'a> {
    /// Respondent claim bound into every challenge and the admission body
    /// (e.g. the join candidate's claimed id).
    pub subject: Option<&'a str>,
    /// Room scope binding (e.g. `"room:valhalla-room-7"` or a join nonce).
    pub context: Option<&'a str>,
    /// Issuance instant; `None` uses the wall clock.
    pub now: Option<OffsetDateTime>,
    /// First seed: challenge `i` uses `seed_base + i`, mirroring the
    /// TypeScript `seedBase` hook for deterministic runs. `None` draws a
    /// fresh uint32 seed per challenge.
    pub seed_base: Option<u64>,
}

/// Mint a room-admission session as the room's gate issuer, mirroring
/// `issueSession` in `bench/gate.ts`: `policy.challenges` sealed
/// challenges, each drawing a cell uniformly from `policy.cells` with
/// replacement via `pick(bound)`, all under one session id and one shared
/// deadline. `generate` is the generator oracle —
/// `(suite_version, family, tier, seed) -> instance` — the same callback
/// shape [`check_admission`] takes.
pub fn issue_room_session(
    policy: &GatePolicy,
    issuer: &SigningKey,
    opts: &RoomSessionOptions<'_>,
    mut pick: impl FnMut(usize) -> usize,
    generate: impl Fn(&str, &str, u32, u64) -> Result<GeneratedInstance, String>,
) -> Result<RoomSession, AttestError> {
    policy.validate()?;
    let cells: Vec<(&str, u64)> = policy
        .cells
        .iter()
        .map(|cell| {
            parse_cell(cell).ok_or_else(|| {
                AttestError::InvalidInput(format!("invalid gate policy: bad cell {cell}"))
            })
        })
        .collect::<Result<_, _>>()?;
    if let Some(base) = opts.seed_base {
        let last = base.checked_add(policy.challenges - 1);
        if !matches!(last, Some(seed) if seed <= u32::MAX as u64) {
            return Err(AttestError::InvalidInput(
                "seedBase must keep every drawn seed a uint32".to_string(),
            ));
        }
    }
    let now = opts.now.unwrap_or_else(OffsetDateTime::now_utc);
    let session_id = format!("gs_{}", random_b64url(9));
    let version = suite_version(&policy.suite);
    let mut tickets = Vec::new();
    for i in 0..policy.challenges {
        let index = pick(cells.len());
        let Some(&(family, tier)) = cells.get(index) else {
            return Err(AttestError::InvalidInput(
                "cell pick fell outside the policy".to_string(),
            ));
        };
        let seed = opts.seed_base.map_or_else(draw_seed, |base| base + i);
        let instance = generate(version, family, tier as u32, seed)
            .map_err(|e| AttestError::Malformed(format!("generator oracle failed: {e}")))?;
        let issued = IssueOptions {
            family,
            tier: tier as u32,
            ttl_seconds: Some(policy.ttl_seconds as i64),
            context: opts.context.map(str::to_string),
            subject: opts.subject.map(str::to_string),
            session_id: Some(session_id.clone()),
            now: Some(now),
        };
        let (_, ticket) = issue_challenge(&issued, seed, &instance, issuer)?;
        tickets.push(ticket);
    }
    Ok(RoomSession {
        protocol: GATE_PROTOCOL.to_string(),
        kind: "session".to_string(),
        session_id,
        policy: policy.clone(),
        subject: opts.subject.map(str::to_string),
        context: opts.context.map(str::to_string),
        issued_at: now
            .format(&Rfc3339)
            .map_err(|e| AttestError::Malformed(e.to_string()))?,
        expires_at: tickets[0].challenge.expires_at.clone(),
        tickets,
    })
}

/// A consumed session: the minted receipts plus the signed admission
/// (mirrors `{receipts, admission}` from `submitSession`).
#[derive(Clone, Debug)]
pub struct RoomSubmission {
    /// One receipt per answered, format-canonical challenge.
    pub receipts: Vec<Receipt>,
    /// The signed admission binding the challenge list, the receipts, and
    /// the verdict.
    pub admission: Admission,
}

/// Consume a room session into its decision, mirroring `submitSession` in
/// `bench/gate.ts`: `responses` keys are challenge ids (a key outside the
/// session is an error); a missing or non-format-canonical response is a
/// failed challenge with no receipt — only canonical responses produce
/// checkable receipts. Every minted receipt is replayed through
/// [`check_receipt_deep`] before the admission is signed, the same
/// issuer-side honesty step the TypeScript submit runs.
pub fn submit_room_session(
    session: &RoomSession,
    responses: &BTreeMap<String, String>,
    issuer: &SigningKey,
    subject_proof: Option<&SubjectProof>,
    now: Option<OffsetDateTime>,
    regenerate: impl Fn(&str, &str, u32, u64) -> Result<GeneratedInstance, String>,
) -> Result<RoomSubmission, AttestError> {
    if session.protocol != GATE_PROTOCOL || session.kind != "session" {
        return Err(AttestError::Malformed("not a gate session".to_string()));
    }
    let now = now.unwrap_or_else(OffsetDateTime::now_utc);
    if now > parse_time(&session.expires_at)? {
        return Err(AttestError::Expired);
    }
    let by_id: HashMap<&str, &Ticket> = session
        .tickets
        .iter()
        .map(|ticket| (ticket.challenge.challenge_id.as_str(), ticket))
        .collect();
    for id in responses.keys() {
        if !by_id.contains_key(id.as_str()) {
            return Err(AttestError::InvalidInput(format!(
                "response for unknown challenge {id}"
            )));
        }
    }
    let mut receipts = Vec::new();
    let mut passed = 0u64;
    for ticket in &session.tickets {
        let Some(response) = responses.get(&ticket.challenge.challenge_id) else {
            continue;
        };
        if canonical_answer(response, answer_format(&ticket.challenge.family)).is_none() {
            continue;
        }
        let challenge = &ticket.challenge;
        let instance = regenerate(
            &challenge.suite_version,
            &challenge.family,
            challenge.tier,
            ticket.seed,
        )
        .map_err(|e| AttestError::Malformed(format!("generator oracle failed: {e}")))?;
        let receipt = verify_response(
            ticket,
            response,
            &instance,
            issuer,
            subject_proof,
            Some(now),
        )?;
        // Issuer-side honesty: replay the minted receipt through the
        // independent checker before it enters the signed admission.
        let replay = check_receipt_deep(&receipt, &regenerate);
        if !replay.ok {
            return Err(AttestError::Mismatch(format!(
                "minted receipt does not verify: {}",
                replay.reason.unwrap_or_default()
            )));
        }
        if replay.verdict == Some(true) {
            passed += 1;
        }
        receipts.push(receipt);
    }
    let body = AdmissionBody {
        kind: "admission".to_string(),
        session_id: session.session_id.clone(),
        policy: session.policy.clone(),
        subject: session.subject.clone(),
        context: session.context.clone(),
        challenges: session.challenges(),
        verdict: AdmissionVerdict {
            pass: passed >= session.policy.min_pass,
            passed,
            required: session.policy.min_pass,
            decided_at: now
                .format(&Rfc3339)
                .map_err(|e| AttestError::Malformed(e.to_string()))?,
        },
        receipts: receipts.clone(),
    };
    let payload = canonical_json(
        &serde_json::to_value(&body).map_err(|e| AttestError::Malformed(e.to_string()))?,
    );
    let signature = b64url(&issuer.sign(payload.as_bytes()).to_bytes());
    let admission = Admission {
        protocol: GATE_PROTOCOL.to_string(),
        payload,
        signature,
    };
    let replay = check_admission(&admission, regenerate);
    if !replay.ok {
        return Err(AttestError::Mismatch(format!(
            "minted admission does not verify: {}",
            replay.reason.unwrap_or_default()
        )));
    }
    Ok(RoomSubmission {
        receipts,
        admission,
    })
}

/// The floor a room pins its admission decision to: the published policy a
/// session must have run under and the verifier key it must have been
/// issued with. Without pinning, `check_admission` verifies *an* admission
/// — pinning makes the decision *this room's*.
pub struct RoomFloor<'a> {
    /// The room's published capability floor.
    pub policy: &'a GatePolicy,
    /// The room's verifier public key, base64url Ed25519 (the `x` member
    /// of its JWK).
    pub verifier_key: String,
}

/// The room's admission decision over a presented admission.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RoomDecision {
    /// Whether the room admits the respondent.
    pub admit: bool,
    /// Why: the verified floor result, the pin mismatch, or the checker's
    /// failure reason.
    pub reason: String,
}

/// Run the room's admission decision: replay the signed admission through
/// [`check_admission`], require it to have run under `floor` (the room's
/// published policy and verifier key), and admit exactly when the signed
/// verdict verifies as a pass. The decision is a pure function of the
/// signed artifact — a claimed verdict, an out-of-band flag, or issuer
/// say-so never enters it.
pub fn decide_room_admission(
    admission: &Admission,
    floor: &RoomFloor<'_>,
    regenerate: impl Fn(&str, &str, u32, u64) -> Result<GeneratedInstance, String>,
) -> RoomDecision {
    let check = check_admission(admission, regenerate);
    if !check.ok {
        return RoomDecision {
            admit: false,
            reason: format!(
                "admission does not verify: {}",
                check.reason.unwrap_or_default()
            ),
        };
    }
    // The admission verifies on its own terms; now decide for *this*
    // room. Pin checks read the already-verified payload: challenges all
    // share one verifier key and the embedded policy already parsed.
    let body: Value = serde_json::from_str(&admission.payload).unwrap_or_default();
    let issued_key = body
        .get("challenges")
        .and_then(Value::as_array)
        .and_then(|challenges| challenges.first())
        .and_then(|challenge| challenge.get("verifier"))
        .and_then(|verifier| verifier.get("publicKey"))
        .and_then(Value::as_str);
    if issued_key != Some(floor.verifier_key.as_str()) {
        return RoomDecision {
            admit: false,
            reason: "admission was not issued under this room's verifier key".to_string(),
        };
    }
    let ran_floor = body
        .get("policy")
        .and_then(|value| GatePolicy::parse(value).ok())
        .is_some_and(|policy| &policy == floor.policy);
    if !ran_floor {
        return RoomDecision {
            admit: false,
            reason: "admission did not run under this room's floor".to_string(),
        };
    }
    match check.verdict {
        Some(true) => RoomDecision {
            admit: true,
            reason: format!(
                "verified: {} passing receipts meet the room floor",
                check.passed.unwrap_or_default()
            ),
        },
        Some(false) => RoomDecision {
            admit: false,
            reason: format!(
                "verified admission misses the room floor: {} of {} required passes",
                check.passed.unwrap_or_default(),
                floor.policy.min_pass
            ),
        },
        None => RoomDecision {
            admit: false,
            reason: "verified admission carries no verdict".to_string(),
        },
    }
}
