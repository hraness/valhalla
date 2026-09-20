//! Local inert puzzle exchange: packing never signs, dials, executes or scores.
use super::{history_cli, Args};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::de::{self, MapAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{json, Value};
use std::{collections::BTreeMap, fmt, path::Path};
use valhalla_clankdar_attest_prototype::{
    canonical_json, Admission, AdmissionBody, Challenge, RoomSession, ATTEST_PROTOCOL,
    GATE_PROTOCOL, MAX_ANSWER_LENGTH, MAX_POLICY_CHALLENGES,
};
use vhalla_room_activity::{
    puzzle_share::{self, Collector, Kind, Part, MAX_ARTIFACT_BYTES, MAX_PARTS},
    RoomScope, SignedEvent, MAX_EVENT_BYTES,
};

const MAX_SESSION_BYTES: usize = 1024 * 1024;
const SCOPE_FLAGS: &[&str] = &[
    "network",
    "realm",
    "directory",
    "room",
    "author",
    "kind",
    "digest",
];
const SEMANTICS: &str = "Signed room frames attribute these exact artifact bytes to the selected application key. Room policy admission, author-chain completeness, puzzle issuer, answer correctness, identity and authority are not established. Check admissions separately with history recent and independently pinned issuer, policy, subject, context and evaluator.";

fn required<'a>(args: &'a Args, name: &str) -> Result<&'a str, String> {
    args.flags
        .get(name)
        .map(String::as_str)
        .ok_or_else(|| format!("exchange requires --{name}"))
}
fn kind_name(kind: Kind) -> &'static str {
    match kind {
        Kind::PublicChallenges => "public-challenges",
        Kind::Responses => "responses",
        Kind::Admission => "admission",
    }
}
fn parse_kind(raw: &str) -> Result<Kind, String> {
    match raw {
        "public-challenges" => Ok(Kind::PublicChallenges),
        "responses" => Ok(Kind::Responses),
        "admission" => Ok(Kind::Admission),
        _ => Err("kind must be public-challenges, responses or admission".into()),
    }
}
fn hex(raw: &[u8]) -> String {
    raw.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn unhex<const N: usize>(raw: &str) -> Result<[u8; N], String> {
    if raw.len() != N * 2
        || !raw
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(format!(
            "expected exactly {} lowercase hex characters",
            N * 2
        ));
    }
    let mut out = [0; N];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&raw[i * 2..i * 2 + 2], 16).map_err(|_| "invalid hex")?;
    }
    Ok(out)
}
fn decode_b64<const N: usize>(raw: &str) -> Result<[u8; N], String> {
    let bytes = URL_SAFE_NO_PAD
        .decode(raw)
        .map_err(|_| "invalid base64url")?;
    if URL_SAFE_NO_PAD.encode(&bytes) != raw {
        return Err("noncanonical base64url".into());
    }
    bytes
        .try_into()
        .map_err(|_| "wrong signature/key length".into())
}
fn bounded_json(raw: &[u8]) -> Result<Value, String> {
    serde_json::from_slice(raw).map_err(|_| "invalid bounded JSON input".into())
}

// Challenge's legacy heldout field is a raw Value. Reconstruct its sole public
// field, too: serializing a typed Challenge alone would leak unknown pool fields.
fn public_challenge(mut challenge: Challenge) -> Result<Challenge, String> {
    if challenge.protocol != ATTEST_PROTOCOL || challenge.kind != "challenge" {
        return Err("not a public challenge".into());
    }
    if let Some(marker) = &challenge.heldout {
        let key = marker
            .get("poolKey")
            .and_then(Value::as_str)
            .ok_or("bad public pool commitment")?;
        unhex::<32>(key)?;
        challenge.heldout = Some(json!({"poolKey": key}));
    }
    Ok(challenge)
}
fn public_session(raw: &[u8]) -> Result<Vec<u8>, String> {
    let session: RoomSession =
        serde_json::from_slice(raw).map_err(|_| "invalid bounded RoomSession")?;
    if session.protocol != GATE_PROTOCOL || session.kind != "session" {
        return Err("expected private RoomSession input for public projection".into());
    }
    session.policy.validate().map_err(|e| e.to_string())?;
    if session.tickets.len() as u64 != session.policy.challenges {
        return Err("session challenge count differs from policy".into());
    }
    let mut challenges = Vec::new();
    let mut ids = std::collections::BTreeSet::new();
    for ticket in session.tickets {
        let challenge = public_challenge(ticket.challenge)?;
        if challenge.session_id.as_deref() != Some(session.session_id.as_str())
            || challenge.expires_at != session.expires_at
            || !ids.insert(challenge.challenge_id.clone())
        {
            return Err("challenge is not uniquely bound to this session and deadline".into());
        }
        challenges.push(challenge);
    }
    // Deliberately construct a new public object; never serialize the session or tickets.
    Ok(canonical_json(&json!({
        "protocol": GATE_PROTOCOL, "kind": "public-challenges", "sessionId": session.session_id,
        "policy": session.policy, "issuedAt": session.issued_at, "expiresAt": session.expires_at,
        "challenges": challenges,
    }))
    .into_bytes())
}

struct Responses(BTreeMap<String, String>);
impl<'de> Deserialize<'de> for Responses {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Unique;
        impl<'de> Visitor<'de> for Unique {
            type Value = Responses;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a bounded unique challenge-id to exact-answer map")
            }
            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
                let mut answers = BTreeMap::new();
                while let Some((id, answer)) = map.next_entry::<String, String>()? {
                    if answers.len() >= MAX_POLICY_CHALLENGES as usize
                        || id.len() > 128
                        || !id.starts_with("att_")
                        || id.len() <= 4
                        || !id
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
                        || answer.len() > MAX_ANSWER_LENGTH
                        || answers.insert(id, answer).is_some()
                    {
                        return Err(de::Error::custom(
                            "invalid, duplicate or oversized response",
                        ));
                    }
                }
                Ok(Responses(answers))
            }
        }
        deserializer.deserialize_map(Unique)
    }
}
fn response_artifact(raw: &[u8]) -> Result<Vec<u8>, String> {
    let answers: Responses =
        serde_json::from_slice(raw).map_err(|_| "invalid bounded response map")?;
    Ok(canonical_json(
        &serde_json::to_value(answers.0).map_err(|_| "response serialization failed")?,
    )
    .into_bytes())
}
fn admission_artifact(raw: &[u8]) -> Result<Vec<u8>, String> {
    let admission: Admission =
        serde_json::from_slice(raw).map_err(|_| "invalid signed admission wrapper")?;
    if admission.protocol != GATE_PROTOCOL {
        return Err("not a gate admission".into());
    }
    let payload = bounded_json(admission.payload.as_bytes())?;
    if canonical_json(&payload) != admission.payload {
        return Err("admission payload is not canonical".into());
    }
    let body: AdmissionBody =
        serde_json::from_value(payload).map_err(|_| "invalid admission body")?;
    if body.kind != "admission"
        || body.challenges.is_empty()
        || body.challenges.len() > MAX_POLICY_CHALLENGES as usize
    {
        return Err("invalid admission challenge list".into());
    }
    let issuer = &body.challenges[0].verifier.public_key;
    if body
        .challenges
        .iter()
        .any(|c| &c.verifier.public_key != issuer)
    {
        return Err("mixed declared issuers".into());
    }
    let key =
        VerifyingKey::from_bytes(&decode_b64(issuer)?).map_err(|_| "invalid declared issuer")?;
    if key.is_weak() {
        return Err("weak declared issuer".into());
    }
    key.verify_strict(
        admission.payload.as_bytes(),
        &Signature::from_bytes(&decode_b64(&admission.signature)?),
    )
    .map_err(|_| "invalid signature from self-declared issuer")?;
    Ok(canonical_json(
        &serde_json::to_value(admission).map_err(|_| "admission serialization failed")?,
    )
    .into_bytes())
}
fn pack_bundle(kind: Kind, raw: &[u8]) -> Result<Value, String> {
    let parts = puzzle_share::pack(kind, raw).map_err(|e| e.to_string())?;
    let first = Part::decode(parts[0].as_str()).map_err(|e| e.to_string())?;
    Ok(json!({
        "protocol": "vhalla-puzzle-share-bundle/1", "kind": kind_name(kind),
        "digest": hex(first.digest()), "artifactBytes": raw.len(),
        "parts": parts.iter().map(|part| part.as_str()).collect::<Vec<_>>(),
        "semantics": "Unsigned inert Text parts. Publish each through the existing room activity signer; this bundle grants no permission. Admission pack checks only its self-declared issuer signature, never an independently pinned issuer or solve.",
    }))
}

struct Pins {
    network: [u8; 32],
    realm: [u8; 16],
    directory: [u8; 32],
    room: [u8; 32],
    author: [u8; 32],
    kind: Kind,
    digest: [u8; 32],
}
impl Pins {
    fn parse(args: &Args) -> Result<Self, String> {
        Ok(Self {
            network: unhex(required(args, "network")?)?,
            realm: unhex(required(args, "realm")?)?,
            directory: unhex(required(args, "directory")?)?,
            room: unhex(required(args, "room")?)?,
            author: unhex(required(args, "author")?)?,
            kind: parse_kind(required(args, "kind")?)?,
            digest: unhex(required(args, "digest")?)?,
        })
    }
    fn check_scope(&self, scope: RoomScope) -> Result<(), String> {
        if scope.network != self.network
            || scope.realm.0.to_be_bytes() != self.realm
            || scope.directory.as_bytes() != &self.directory
            || scope.room.as_bytes() != &self.room
        {
            return Err(
                "signed activity differs from the explicitly selected full room scope".into(),
            );
        }
        Ok(())
    }
    fn metadata(&self, length: usize) -> Value {
        json!({"protocol": "vhalla-puzzle-share-export/1", "scope": {
            "network": hex(&self.network), "realm": hex(&self.realm), "directory": hex(&self.directory), "room": hex(&self.room)},
            "sharer": hex(&self.author), "kind": kind_name(self.kind), "digest": hex(&self.digest),
            "artifactBytes": length, "frameSignaturesChecked": true, "semantics": SEMANTICS})
    }
}
fn collect_files(files: &[String], pins: &Pins) -> Result<Vec<u8>, String> {
    if files.is_empty() || files.len() > MAX_PARTS {
        return Err(format!(
            "collect requires 1–{MAX_PARTS} saved binary activity frames"
        ));
    }
    let mut collector = None;
    for path in files {
        let raw = history_cli::read(path, MAX_EVENT_BYTES)?;
        let event = SignedEvent::decode(&raw)
            .and_then(SignedEvent::verify)
            .map_err(|e| e.to_string())?;
        pins.check_scope(event.claims().scope)?;
        if collector.is_none() {
            collector = Some(
                Collector::new(event.claims().scope, pins.author, pins.kind, pins.digest)
                    .map_err(|e| e.to_string())?,
            );
        }
        collector
            .as_mut()
            .ok_or("missing collector")?
            .push(&event)
            .map_err(|e| e.to_string())?;
    }
    collector
        .ok_or("missing collector")?
        .into_bytes()
        .map_err(|e| e.to_string())
}

/// Publish only fully checked bytes, without replacing any existing path. The
/// operator owns the selected parent directory; this is not hostile-owner custody.
#[cfg(unix)]
fn write_new(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use rand_core::RngCore;
    use std::{fs, io::Write, os::unix::fs::OpenOptionsExt};
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let directory = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(parent)
        .map_err(|_| "output parent must be an existing nonsymlink directory")?;
    let mut nonce = [0; 16];
    rand_core::OsRng.fill_bytes(&mut nonce);
    let temporary = parent.join(format!(".puzzle-share-{}.tmp", hex(&nonce)));
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&temporary)
        .map_err(|_| "cannot create private output staging file")?;
    let result = (|| {
        file.write_all(bytes)
            .and_then(|_| file.sync_all())
            .map_err(|_| "could not persist complete staged output")?;
        fs::hard_link(&temporary, path)
            .map_err(|_| "cannot publish output: destination must not exist")?;
        directory
            .sync_all()
            .map_err(|_| "output published but directory sync failed; retain and inspect output")?;
        Ok(())
    })();
    drop(file);
    if fs::remove_file(&temporary).is_ok() {
        let _ = directory.sync_all();
    }
    result
}
#[cfg(not(unix))]
fn write_new(_: &Path, _: &[u8]) -> Result<(), String> {
    Err("exchange output requires Unix file guards".into())
}

fn execute(args: &Args) -> Result<Value, String> {
    let command = args
        .positional
        .first()
        .map(String::as_str)
        .ok_or("exchange requires challenges, responses, admission or collect")?;
    let collecting = command == "collect";
    for (name, values) in &args.flag_lists {
        if (name != "out" && (!collecting || !SCOPE_FLAGS.contains(&name.as_str())))
            || values.len() != 1
        {
            return Err(format!("unsupported or repeated exchange option --{name}"));
        }
    }
    if !args.switches.is_empty() {
        return Err("unsupported exchange switch".into());
    }
    let out = Path::new(required(args, "out")?);
    if collecting {
        let pins = Pins::parse(args)?;
        let raw = collect_files(&args.positional[1..], &pins)?;
        write_new(out, &raw)?;
        return Ok(pins.metadata(raw.len()));
    }
    if args.positional.len() != 2 {
        return Err("packing requires exactly one input file".into());
    }
    let kind = match command {
        "challenges" => Kind::PublicChallenges,
        "responses" => Kind::Responses,
        "admission" => Kind::Admission,
        _ => return Err("unknown exchange command".into()),
    };
    let raw = history_cli::read(
        &args.positional[1],
        if kind == Kind::PublicChallenges {
            MAX_SESSION_BYTES
        } else {
            MAX_ARTIFACT_BYTES
        },
    )?;
    let artifact = match kind {
        Kind::PublicChallenges => public_session(&raw)?,
        Kind::Responses => response_artifact(&raw)?,
        Kind::Admission => admission_artifact(&raw)?,
    };
    let bundle = pack_bundle(kind, &artifact)?;
    write_new(out, canonical_json(&bundle).as_bytes())?;
    Ok(
        json!({"kind": kind_name(kind), "digest": bundle["digest"], "artifactBytes": artifact.len(), "partCount": bundle["parts"].as_array().ok_or("invalid parts")?.len(), "output": out}),
    )
}
pub(super) fn run(args: &Args) -> Result<(), String> {
    println!("{}", canonical_json(&execute(args)?));
    Ok(())
}

#[cfg(test)]
#[path = "room_exchange_tests.rs"]
mod tests;
