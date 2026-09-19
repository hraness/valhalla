//! `clankdar-attest` — sealed-seed capability attestation CLI.
//!
//!   clankdar-attest keygen --out KEY.json
//!   clankdar-attest issue --key KEY.json (--suite NAME | --suite-version VER) --family F --tier N [--seed N] [--ttl S] [--context TXT] [--out TICKET.json] [--clankdar DIR]
//!   clankdar-attest verify --key KEY.json --ticket TICKET.json --response-file FILE [--subject-key KEY.json] [--out RECEIPT.json] [--clankdar DIR]
//!   clankdar-attest check RECEIPT_OR_ADMISSION.json [--deep] [--clankdar DIR]
//!   clankdar-attest tlog check TLOG.json
//!   clankdar-attest tlog prove TLOG.json --session gs_x
//!   clankdar-attest tlog admit TLOG.json ADMISSION.json [--clankdar DIR]
//!   clankdar-attest rooms issue --key KEY.json --policy POLICY.json [--subject TXT] [--context TXT] [--seed-base N] [--out SESSION.json] [--clankdar DIR]
//!   clankdar-attest rooms submit --key KEY.json --session SESSION.json --responses FILE [--subject-proof PROOF.json] [--out ADMISSION.json] [--clankdar DIR]
//!   clankdar-attest rooms prove --key KEY.json --challenge CHALLENGE.json
//!   clankdar-attest rooms decide ADMISSION.json --policy POLICY.json --key KEY.json [--clankdar DIR]
//!
//! `check` on a receipt is fully offline. `issue`, `verify`, `check --deep`,
//! and the rooms issue/submit/decide modes call the canonical Clankdar
//! generator oracle (`bun bench/instance.ts`) inside `--clankdar` (default:
//! `$CLANKDAR_DIR`, then `../clankdar`). Admission checking regenerates every
//! embedded receipt, so the oracle is required. `tlog check`, `tlog prove`,
//! and `rooms prove` are fully offline; `tlog admit` replays the admission's
//! embedded receipts through the oracle like `check` does.
//!
//! The `rooms` modes dogfood the room-side gate-v1 flow: a room publishes
//! a `GatePolicy` floor and verifier key, `rooms issue` mints a session,
//! `rooms submit` consumes responses into a signed admission, and `rooms
//! decide` replays a presented admission through `check_admission` pinned
//! to the room's own floor and key — printing `{"admit": bool, "reason"}`
//! and exiting nonzero on deny.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::exit;
use std::{env, fs};

use ed25519_dalek::SigningKey;
use serde::Serialize;
use valhalla_clankdar_attest_prototype::{
    check_admission, check_log, check_logged_admission, check_receipt, check_receipt_deep,
    decide_room_admission, draw_seed, generate_verifier, issue_challenge, issue_room_session,
    key_id_of, prove_session, signing_key, subject_proof_for, submit_room_session, verify_response,
    Admission, AttestError, Challenge, GatePolicy, GeneratedInstance, IssueOptions, Receipt,
    RoomFloor, RoomSession, RoomSessionOptions, SubjectProof, Ticket, VerifierJwk, GATE_PROTOCOL,
};

const USAGE: &str = "usage: clankdar-attest keygen --out KEY.json | issue --key KEY.json (--suite v2|frontier|agent | --suite-version VERSION) --family NAME --tier N [--seed N] [--ttl SEC] [--context TEXT] [--out TICKET.json] [--clankdar DIR] | verify --key KEY.json --ticket TICKET.json --response-file FILE [--subject-key KEY.json] [--out RECEIPT.json] [--clankdar DIR] | check RECEIPT_OR_ADMISSION.json [--deep] [--clankdar DIR] | tlog check TLOG.json | tlog prove TLOG.json --session gs_x | tlog admit TLOG.json ADMISSION.json [--clankdar DIR] | rooms issue --key KEY.json --policy POLICY.json [--subject TEXT] [--context TEXT] [--seed-base N] [--out SESSION.json] [--clankdar DIR] | rooms submit --key KEY.json --session SESSION.json --responses FILE [--subject-proof PROOF.json] [--out ADMISSION.json] [--clankdar DIR] | rooms prove --key KEY.json --challenge CHALLENGE.json | rooms decide ADMISSION.json --policy POLICY.json --key KEY.json [--clankdar DIR]";

struct Args {
    flags: std::collections::HashMap<String, String>,
    switches: std::collections::HashSet<String>,
    positional: Vec<String>,
}

fn parse_args(argv: &[String]) -> Result<Args, String> {
    let mut args = Args {
        flags: std::collections::HashMap::new(),
        switches: std::collections::HashSet::new(),
        positional: Vec::new(),
    };
    let mut i = 0;
    while i < argv.len() {
        let arg = &argv[i];
        if let Some(name) = arg.strip_prefix("--") {
            if name == "deep" || name == "help" {
                args.switches.insert(name.to_string());
            } else {
                i += 1;
                let value = argv
                    .get(i)
                    .ok_or_else(|| format!("--{name} requires a value"))?;
                args.flags.insert(name.to_string(), value.clone());
            }
        } else {
            args.positional.push(arg.clone());
        }
        i += 1;
    }
    Ok(args)
}

fn clankdar_dir(args: &Args) -> PathBuf {
    if let Some(dir) = args.flags.get("clankdar") {
        return PathBuf::from(dir);
    }
    if let Ok(dir) = env::var("CLANKDAR_DIR") {
        return PathBuf::from(dir);
    }
    PathBuf::from("../clankdar")
}

/// The generator oracle: `bun bench/instance.ts` inside the clankdar repo.
fn oracle(
    dir: &Path,
    suite: &str,
    suite_is_version: bool,
    family: &str,
    tier: u32,
    seed: u64,
) -> Result<GeneratedInstance, AttestError> {
    let suite_flag = if suite_is_version {
        "--suite-version"
    } else {
        "--suite"
    };
    let output = std::process::Command::new("bun")
        .args([
            "bench/instance.ts",
            suite_flag,
            suite,
            "--family",
            family,
            "--tier",
            &tier.to_string(),
            "--seed",
            &seed.to_string(),
        ])
        .current_dir(dir)
        .output()
        .map_err(|e| AttestError::Malformed(format!("cannot run generator oracle: {e}")))?;
    if !output.status.success() {
        return Err(AttestError::Malformed(format!(
            "generator oracle failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    serde_json::from_slice(&output.stdout)
        .map_err(|e| AttestError::Malformed(format!("generator oracle returned bad JSON: {e}")))
}

fn read_json<T: serde::de::DeserializeOwned>(path: &str) -> Result<T, AttestError> {
    let text = fs::read_to_string(path)
        .map_err(|e| AttestError::Malformed(format!("cannot read {path}: {e}")))?;
    serde_json::from_str(&text)
        .map_err(|e| AttestError::Malformed(format!("cannot parse {path}: {e}")))
}

fn write_json(path: &str, value: &impl Serialize, private: bool) -> Result<(), AttestError> {
    if Path::new(path).exists() {
        return Err(AttestError::InvalidInput(format!(
            "refusing to overwrite {path}"
        )));
    }
    let text = format!(
        "{}\n",
        serde_json::to_string_pretty(value).map_err(|e| AttestError::Malformed(e.to_string()))?
    );
    fs::write(path, text)
        .map_err(|e| AttestError::Malformed(format!("cannot write {path}: {e}")))?;
    if private {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
        }
    }
    Ok(())
}

fn fail(error: AttestError) -> ! {
    eprintln!("{error}");
    exit(2)
}

fn flag<'a>(args: &'a Args, names: &[&str], mode: &str) -> &'a str {
    for name in names {
        if let Some(value) = args.flags.get(*name) {
            return value;
        }
    }
    fail(AttestError::InvalidInput(format!(
        "rooms {mode} requires --{}",
        names.join(" ")
    )))
}

/// The room's verifier public key: a JWK `x` member or a bare base64url
/// string — the public half is all the decision pins.
fn read_public_key(path: &str) -> Result<String, AttestError> {
    let text = fs::read_to_string(path)
        .map_err(|e| AttestError::Malformed(format!("cannot read {path}: {e}")))?;
    let value: serde_json::Value = serde_json::from_str(&text)
        .map_err(|e| AttestError::Malformed(format!("cannot parse {path}: {e}")))?;
    if let Some(x) = value.get("x").and_then(|v| v.as_str()) {
        return Ok(x.to_string());
    }
    if let Some(raw) = value.as_str() {
        return Ok(raw.to_string());
    }
    Err(AttestError::Malformed(format!(
        "{path} does not carry a verifier public key"
    )))
}

/// `rooms issue`: mint a room-admission session as the room-side issuer —
/// `policy.challenges` sealed challenges under one session id and one
/// deadline. The session file is private (it carries the seeds); stdout
/// carries the public challenge list the respondent sees.
fn rooms_issue(args: &Args) {
    let key_path = flag(args, &["key"], "issue");
    let policy_path = flag(args, &["policy"], "issue");
    let value: serde_json::Value = match read_json(policy_path) {
        Ok(v) => v,
        Err(e) => fail(e),
    };
    let policy = match GatePolicy::parse(&value) {
        Ok(p) => p,
        Err(e) => fail(e),
    };
    let jwk: VerifierJwk = match read_json(key_path) {
        Ok(j) => j,
        Err(e) => fail(e),
    };
    let key = match signing_key(&jwk) {
        Ok(k) => k,
        Err(e) => fail(e),
    };
    let seed_base = match args.flags.get("seed-base") {
        Some(s) => match s.parse() {
            Ok(v) => Some(v),
            Err(_) => fail(AttestError::InvalidInput(
                "--seed-base must be a uint32 seed".to_string(),
            )),
        },
        None => None,
    };
    let opts = RoomSessionOptions {
        subject: args.flags.get("subject").map(String::as_str),
        context: args.flags.get("context").map(String::as_str),
        now: None,
        seed_base,
    };
    let dir = clankdar_dir(args);
    let mut rng = rand_core::OsRng;
    let session = match issue_room_session(
        &policy,
        &key,
        &opts,
        |bound| (rand_core::RngCore::next_u64(&mut rng) % bound as u64) as usize,
        |suite_version, family, tier, seed| {
            oracle(&dir, suite_version, true, family, tier, seed).map_err(|e| e.to_string())
        },
    ) {
        Ok(s) => s,
        Err(e) => fail(e),
    };
    let published = serde_json::json!({
        "sessionId": session.session_id,
        "expiresAt": session.expires_at,
        "challenges": session.challenges(),
    });
    match args.flags.get("out") {
        Some(out) => {
            if let Err(e) = write_json(out, &session, true) {
                fail(e);
            }
            println!(
                "{}",
                serde_json::to_string_pretty(&published).unwrap_or_default()
            );
        }
        None => println!(
            "{}",
            serde_json::to_string_pretty(
                &serde_json::json!({"session": session, "published": published})
            )
            .unwrap_or_default()
        ),
    }
}

/// `rooms submit`: consume the respondent's answers (a JSON object keyed
/// by challenge id) into the signed admission — one receipt per answered,
/// format-canonical challenge, each replayed before the verdict is signed.
fn rooms_submit(args: &Args) {
    let key_path = flag(args, &["key"], "submit");
    let session_path = flag(args, &["session"], "submit");
    let responses_path = flag(args, &["responses"], "submit");
    let jwk: VerifierJwk = match read_json(key_path) {
        Ok(j) => j,
        Err(e) => fail(e),
    };
    let key = match signing_key(&jwk) {
        Ok(k) => k,
        Err(e) => fail(e),
    };
    let session: RoomSession = match read_json(session_path) {
        Ok(s) => s,
        Err(e) => fail(e),
    };
    let responses: BTreeMap<String, String> = match read_json(responses_path) {
        Ok(r) => r,
        Err(e) => fail(e),
    };
    // The respondent hands over a session-scoped proof minted on its own
    // side (`rooms prove`); the issuer never touches the respondent key.
    let subject_proof: Option<SubjectProof> = match args.flags.get("subject-proof") {
        Some(path) => match read_json(path) {
            Ok(p) => Some(p),
            Err(e) => fail(e),
        },
        None => None,
    };
    let dir = clankdar_dir(args);
    let submission = match submit_room_session(
        &session,
        &responses,
        &key,
        subject_proof.as_ref(),
        None,
        |suite_version, family, tier, seed| {
            oracle(&dir, suite_version, true, family, tier, seed).map_err(|e| e.to_string())
        },
    ) {
        Ok(s) => s,
        Err(e) => fail(e),
    };
    match args.flags.get("out") {
        Some(out) => {
            if let Err(e) = write_json(out, &submission.admission, false) {
                fail(e);
            }
        }
        None => println!(
            "{}",
            serde_json::to_string_pretty(&submission.admission).unwrap_or_default()
        ),
    }
}

/// `rooms prove`: the respondent's half — mint a subject proof for a
/// session challenge the room published. Session-bound challenges scope
/// the proof to the whole session, so any listed challenge works.
fn rooms_prove(args: &Args) {
    let key_path = flag(args, &["key"], "prove");
    let challenge_path = flag(args, &["challenge"], "prove");
    let jwk: VerifierJwk = match read_json(key_path) {
        Ok(j) => j,
        Err(e) => fail(e),
    };
    let challenge: Challenge = match read_json(challenge_path) {
        Ok(c) => c,
        Err(e) => fail(e),
    };
    match subject_proof_for(&challenge, &jwk) {
        Ok(proof) => println!(
            "{}",
            serde_json::to_string_pretty(&proof).unwrap_or_default()
        ),
        Err(e) => fail(e),
    }
}

/// `rooms decide`: the room's admission decision — replay the presented
/// admission through `check_admission` pinned to the room's published
/// floor and verifier key, then print `{"admit": bool, "reason"}` for a
/// room gate to consume. Deny is a decision, not a crash: the verdict
/// prints and the exit code is nonzero. For a policy-agnostic replay, use
/// plain `check`.
fn rooms_decide(args: &Args) {
    let Some(path) = args.positional.get(1) else {
        fail(AttestError::InvalidInput(
            "rooms decide requires an admission file".to_string(),
        ));
    };
    let policy_path = flag(args, &["policy"], "decide");
    let key_path = flag(args, &["key"], "decide");
    let admission: Admission = match read_json(path) {
        Ok(a) => a,
        Err(e) => fail(e),
    };
    let value: serde_json::Value = match read_json(policy_path) {
        Ok(v) => v,
        Err(e) => fail(e),
    };
    let policy = match GatePolicy::parse(&value) {
        Ok(p) => p,
        Err(e) => fail(e),
    };
    let verifier_key = match read_public_key(key_path) {
        Ok(k) => k,
        Err(e) => fail(e),
    };
    let floor = RoomFloor {
        policy: &policy,
        verifier_key,
    };
    let dir = clankdar_dir(args);
    let decision =
        decide_room_admission(&admission, &floor, |suite_version, family, tier, seed| {
            oracle(&dir, suite_version, true, family, tier, seed).map_err(|e| e.to_string())
        });
    println!("{}", serde_json::to_string(&decision).unwrap_or_default());
    if !decision.admit {
        exit(2);
    }
}

fn main() {
    let argv: Vec<String> = env::args().skip(1).collect();
    let Some(command) = argv.first() else {
        println!("{USAGE}");
        return;
    };
    let args = match parse_args(&argv[1..]) {
        Ok(args) => args,
        Err(e) => fail(AttestError::InvalidInput(e)),
    };
    if args.switches.contains("help") {
        println!("{USAGE}");
        return;
    }
    match command.as_str() {
        "keygen" => {
            let Some(out) = args.flags.get("out") else {
                fail(AttestError::InvalidInput(
                    "keygen requires --out".to_string(),
                ));
            };
            let jwk = generate_verifier();
            if let Err(e) = write_json(out, &jwk, true) {
                fail(e);
            }
            let public_key = jwk.x.clone();
            let key_id = key_id_of(&public_key).unwrap_or_default();
            println!(
                "{}",
                serde_json::json!({"keyId": key_id, "publicKey": public_key, "privateKeyFile": out})
            );
        }
        "issue" => {
            let (Some(key_path), Some(family), Some(tier)) = (
                args.flags.get("key"),
                args.flags.get("family"),
                args.flags.get("tier"),
            ) else {
                fail(AttestError::InvalidInput(
                    "issue requires --key --family --tier".to_string(),
                ));
            };
            let (suite, suite_is_version) =
                match (args.flags.get("suite"), args.flags.get("suite-version")) {
                    (Some(s), None) => (s.clone(), false),
                    (None, Some(v)) => (v.clone(), true),
                    _ => fail(AttestError::InvalidInput(
                        "issue requires exactly one of --suite or --suite-version".to_string(),
                    )),
                };
            let tier: u32 = match tier.parse() {
                Ok(t) => t,
                Err(_) => fail(AttestError::InvalidInput(
                    "tier must be a non-negative integer".to_string(),
                )),
            };
            let seed: u64 = match args.flags.get("seed") {
                Some(s) => match s.parse() {
                    Ok(v) => v,
                    Err(_) => fail(AttestError::InvalidInput(
                        "seed must be a uint32".to_string(),
                    )),
                },
                None => draw_seed(),
            };
            let jwk: VerifierJwk = match read_json(key_path) {
                Ok(j) => j,
                Err(e) => fail(e),
            };
            let key: SigningKey = match signing_key(&jwk) {
                Ok(k) => k,
                Err(e) => fail(e),
            };
            let dir = clankdar_dir(&args);
            let instance = match oracle(&dir, &suite, suite_is_version, family, tier, seed) {
                Ok(i) => i,
                Err(e) => fail(e),
            };
            let opts = IssueOptions {
                family,
                tier,
                ttl_seconds: args.flags.get("ttl").and_then(|t| t.parse().ok()),
                context: args.flags.get("context").cloned(),
                subject: None,
                session_id: None,
                now: None,
            };
            let (challenge, ticket) = match issue_challenge(&opts, seed, &instance, &key) {
                Ok(v) => v,
                Err(e) => fail(e),
            };
            match args.flags.get("out") {
                Some(out) => {
                    if let Err(e) = write_json(out, &ticket, true) {
                        fail(e);
                    }
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&challenge).unwrap_or_default()
                    );
                }
                None => println!(
                    "{}",
                    serde_json::to_string_pretty(
                        &serde_json::json!({"challenge": challenge, "ticket": ticket})
                    )
                    .unwrap_or_default()
                ),
            }
        }
        "verify" => {
            let (Some(key_path), Some(ticket_path), Some(response_path)) = (
                args.flags.get("key"),
                args.flags.get("ticket"),
                args.flags.get("response-file"),
            ) else {
                fail(AttestError::InvalidInput(
                    "verify requires --key --ticket --response-file".to_string(),
                ));
            };
            let jwk: VerifierJwk = match read_json(key_path) {
                Ok(j) => j,
                Err(e) => fail(e),
            };
            let key = match signing_key(&jwk) {
                Ok(k) => k,
                Err(e) => fail(e),
            };
            let ticket: Ticket = match read_json(ticket_path) {
                Ok(t) => t,
                Err(e) => fail(e),
            };
            let response = match fs::read_to_string(response_path) {
                Ok(r) => r.trim().to_string(),
                Err(e) => fail(AttestError::Malformed(format!(
                    "cannot read {response_path}: {e}"
                ))),
            };
            let dir = clankdar_dir(&args);
            let c = &ticket.challenge;
            let instance =
                match oracle(&dir, &c.suite_version, true, &c.family, c.tier, ticket.seed) {
                    Ok(i) => i,
                    Err(e) => fail(e),
                };
            // `--subject-key` mints one respondent proof for this challenge —
            // session-scoped when the challenge carries a `sessionId`.
            let subject_proof = match args.flags.get("subject-key") {
                Some(path) => {
                    let respondent: VerifierJwk = match read_json(path) {
                        Ok(j) => j,
                        Err(e) => fail(e),
                    };
                    match subject_proof_for(&ticket.challenge, &respondent) {
                        Ok(proof) => Some(proof),
                        Err(e) => fail(e),
                    }
                }
                None => None,
            };
            let receipt = match verify_response(
                &ticket,
                &response,
                &instance,
                &key,
                subject_proof.as_ref(),
                None,
            ) {
                Ok(r) => r,
                Err(e) => fail(e),
            };
            match args.flags.get("out") {
                Some(out) => {
                    if let Err(e) = write_json(out, &receipt, false) {
                        fail(e);
                    }
                }
                None => println!(
                    "{}",
                    serde_json::to_string_pretty(&receipt).unwrap_or_default()
                ),
            }
        }
        "check" => {
            let Some(path) = args.positional.first() else {
                fail(AttestError::InvalidInput(
                    "check requires a receipt or admission file".to_string(),
                ));
            };
            let value: serde_json::Value = match read_json(path) {
                Ok(v) => v,
                Err(e) => fail(e),
            };
            if value.get("protocol").and_then(|p| p.as_str()) == Some(GATE_PROTOCOL) {
                let admission: Admission = match serde_json::from_value(value) {
                    Ok(a) => a,
                    Err(e) => fail(AttestError::Malformed(format!("cannot parse {path}: {e}"))),
                };
                // Admission checking always regenerates embedded receipts —
                // the deep path is inherent, so the oracle is required.
                let dir = clankdar_dir(&args);
                let result = check_admission(&admission, |suite_version, family, tier, seed| {
                    oracle(&dir, suite_version, true, family, tier, seed).map_err(|e| e.to_string())
                });
                println!("{}", serde_json::to_string(&result).unwrap_or_default());
                if !result.ok {
                    exit(2);
                }
                return;
            }
            let receipt: Receipt = match serde_json::from_value(value) {
                Ok(r) => r,
                Err(e) => fail(AttestError::Malformed(format!("cannot parse {path}: {e}"))),
            };
            let result = if args.switches.contains("deep") {
                let dir = clankdar_dir(&args);
                check_receipt_deep(&receipt, |suite_version, family, tier, seed| {
                    oracle(&dir, suite_version, true, family, tier, seed).map_err(|e| e.to_string())
                })
            } else {
                check_receipt(&receipt)
            };
            println!("{}", serde_json::to_string(&result).unwrap_or_default());
            if !result.ok {
                exit(2);
            }
        }
        // `tlog` dispatches on its own subcommand, like `check` dispatches
        // on the protocol field: `tlog check|prove|admit`.
        "tlog" => {
            let Some(sub) = args.positional.first().map(String::as_str) else {
                fail(AttestError::InvalidInput(format!(
                    "tlog requires a command. {USAGE}"
                )));
            };
            match sub {
                "check" => {
                    let Some(path) = args.positional.get(1) else {
                        fail(AttestError::InvalidInput(
                            "tlog check requires a TLOG.json file".to_string(),
                        ));
                    };
                    let log: serde_json::Value = match read_json(path) {
                        Ok(v) => v,
                        Err(e) => fail(e),
                    };
                    let result = check_log(&log);
                    println!("{}", serde_json::to_string(&result).unwrap_or_default());
                    if !result.ok {
                        exit(2);
                    }
                }
                "prove" => {
                    let (Some(path), Some(session)) =
                        (args.positional.get(1), args.flags.get("session"))
                    else {
                        fail(AttestError::InvalidInput(
                            "tlog prove requires TLOG.json and --session".to_string(),
                        ));
                    };
                    let log: serde_json::Value = match read_json(path) {
                        Ok(v) => v,
                        Err(e) => fail(e),
                    };
                    match prove_session(&log, session) {
                        Ok(proof) => println!(
                            "{}",
                            serde_json::to_string_pretty(&proof).unwrap_or_default()
                        ),
                        Err(e) => fail(e),
                    }
                }
                "admit" => {
                    let (Some(log_path), Some(admission_path)) =
                        (args.positional.get(1), args.positional.get(2))
                    else {
                        fail(AttestError::InvalidInput(
                            "tlog admit requires TLOG.json and ADMISSION.json".to_string(),
                        ));
                    };
                    let log: serde_json::Value = match read_json(log_path) {
                        Ok(v) => v,
                        Err(e) => fail(e),
                    };
                    let admission: Admission = match read_json(admission_path) {
                        Ok(v) => v,
                        Err(e) => fail(e),
                    };
                    // Admission checking always regenerates embedded
                    // receipts — the deep path is inherent, so the oracle
                    // is required.
                    let dir = clankdar_dir(&args);
                    let result =
                        check_logged_admission(&log, &admission, |sv, family, tier, seed| {
                            oracle(&dir, sv, true, family, tier, seed).map_err(|e| e.to_string())
                        });
                    println!("{}", serde_json::to_string(&result).unwrap_or_default());
                    if !result.ok {
                        exit(2);
                    }
                }
                other => fail(AttestError::InvalidInput(format!(
                    "unknown tlog command: {other}. {USAGE}"
                ))),
            }
        }
        "rooms" => match args.positional.first().map(String::as_str) {
            Some("issue") => rooms_issue(&args),
            Some("submit") => rooms_submit(&args),
            Some("prove") => rooms_prove(&args),
            Some("decide") => rooms_decide(&args),
            other => fail(AttestError::InvalidInput(format!(
                "rooms requires issue|submit|prove|decide, got {}. {USAGE}",
                other.unwrap_or("nothing")
            ))),
        },
        other => fail(AttestError::InvalidInput(format!(
            "unknown command: {other}. {USAGE}"
        ))),
    }
}
