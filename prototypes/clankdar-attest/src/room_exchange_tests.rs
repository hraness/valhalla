use super::*;
use ed25519_dalek::SigningKey;
use rand_core::RngCore;
use std::{fs, path::PathBuf};
use vhalla_room_activity::{Content, UnsignedEvent};

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let mut nonce = [0; 16];
        rand_core::OsRng.fill_bytes(&mut nonce);
        let path = std::env::temp_dir().join(format!("clankdar-exchange-test-{}", hex(&nonce)));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn file(&self, name: &str, bytes: &[u8]) -> String {
        let path = self.0.join(name);
        fs::write(&path, bytes).unwrap();
        path.to_str().unwrap().into()
    }
    fn absent(&self, name: &str) -> String {
        self.0.join(name).to_str().unwrap().into()
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn fixture() -> Value {
    serde_json::from_str(include_str!("../tests/fixtures/ts_algal_compat.json")).unwrap()
}
fn admission() -> Value {
    fixture()["admission"].clone()
}
fn public_input() -> Value {
    let body: Value = serde_json::from_str(admission()["payload"].as_str().unwrap()).unwrap();
    let tickets: Vec<_> = body["challenges"].as_array().unwrap().iter().map(|challenge| {
        let mut challenge = challenge.clone();
        challenge["unknownIssuerPrivate"] = json!("PRIVATE-CHALLENGE-EXTRA");
        challenge["verifier"]["d"] = json!("PRIVATE-KEY-EXTRA");
        challenge["heldout"] = json!({"poolKey": "ab".repeat(32), "label": "PRIVATE-POOL-LABEL"});
        json!({"challenge": challenge, "seed": 987654321, "expected": "PRIVATE-EXPECTED-ANSWER", "ticketExtra": "PRIVATE-TICKET-EXTRA"})
    }).collect();
    json!({"protocol": GATE_PROTOCOL, "kind": "session", "sessionId": body["sessionId"], "policy": body["policy"],
        "issuedAt": "2026-09-19T00:00:00.000Z", "expiresAt": body["challenges"][0]["expiresAt"],
        "tickets": tickets, "issuerSeed": "PRIVATE-ISSUER-SEED", "pool": {"label": "PRIVATE-POOL-EXTRA"}})
}
fn args(values: &[&str]) -> Args {
    super::super::parse_args(&values.iter().map(|v| (*v).into()).collect::<Vec<_>>()).unwrap()
}
fn key() -> SigningKey {
    SigningKey::from_bytes(&[42; 32])
}
// A real canonical unsigned frame; decode/sign use the production codec. The
// binary fixture avoids introducing core/rooms dependencies solely for tests.
fn event(text: &str, key: &SigningKey) -> SignedEvent {
    let mut raw = b"VHRA\x01".to_vec();
    raw.extend([7; 32]);
    raw.extend(77u128.to_be_bytes());
    raw.extend([5; 32]);
    raw.extend([8; 32]);
    raw.extend([9; 32]);
    raw.extend(key.verifying_key().to_bytes());
    raw.extend(1u64.to_be_bytes());
    raw.extend([0; 32]);
    raw.extend(1234u64.to_be_bytes());
    raw.push(0);
    raw.extend((text.len() as u16).to_be_bytes());
    raw.extend(text.as_bytes());
    UnsignedEvent::decode(&raw)
        .unwrap()
        .sign_with_key(key)
        .unwrap()
}
fn pins(kind: Kind, raw: &[u8]) -> Pins {
    let part = Part::decode(puzzle_share::pack(kind, raw).unwrap()[0].as_str()).unwrap();
    Pins {
        network: [7; 32],
        realm: 77u128.to_be_bytes(),
        directory: [5; 32],
        room: [8; 32],
        author: key().verifying_key().to_bytes(),
        kind,
        digest: *part.digest(),
    }
}
fn collect_args(p: &Pins, files: &[String], out: &str) -> Args {
    let mut all = vec!["collect".into()];
    all.extend_from_slice(files);
    for (flag, value) in [
        ("network", hex(&p.network)),
        ("realm", hex(&p.realm)),
        ("directory", hex(&p.directory)),
        ("room", hex(&p.room)),
        ("author", hex(&p.author)),
        ("kind", kind_name(p.kind).into()),
        ("digest", hex(&p.digest)),
        ("out", out.into()),
    ] {
        all.extend([format!("--{flag}"), value]);
    }
    super::super::parse_args(&all).unwrap()
}
fn frames(dir: &Scratch, kind: Kind, raw: &[u8]) -> Vec<String> {
    puzzle_share::pack(kind, raw)
        .unwrap()
        .iter()
        .enumerate()
        .map(|(i, part)| {
            dir.file(
                &format!("{i}.frame"),
                &event(part.as_str(), &key()).encode(),
            )
        })
        .collect()
}

#[test]
fn public_projection_cannot_serialize_private_ticket_seed_answer_pool_or_unknown_fields() {
    let raw = public_session(&serde_json::to_vec(&public_input()).unwrap()).unwrap();
    let text = std::str::from_utf8(&raw).unwrap();
    assert!(!text.contains("PRIVATE-"));
    assert!(!text.contains("987654321"));
    for private in [
        "\"tickets\"",
        "\"seed\":",
        "\"expected\":",
        "\"pool\":",
        "\"label\":",
        "\"d\":",
    ] {
        assert!(!text.contains(private), "{private}");
    }
    let public: Value = serde_json::from_slice(&raw).unwrap();
    assert_eq!(public["kind"], "public-challenges");
    assert_eq!(
        public["challenges"][0]["heldout"],
        json!({"poolKey": "ab".repeat(32)})
    );
    assert!(public["challenges"][0]["prompt"]
        .as_str()
        .unwrap()
        .contains("algal.expr.v1"));
    let mut wrong = public_input();
    wrong["tickets"][0]["challenge"]["sessionId"] = json!("gs_different");
    assert!(public_session(&serde_json::to_vec(&wrong).unwrap()).is_err());
}

#[test]
fn response_map_is_canonical_exact_bounded_and_duplicate_free() {
    assert_eq!(
        response_artifact(br#"{"att_z":"+0012","att_a":" 12\n"}"#).unwrap(),
        br#"{"att_a":" 12\n","att_z":"+0012"}"#
    );
    assert_eq!(response_artifact(b"{}").unwrap(), b"{}");
    for invalid in [
        br#"{"att_a":"1","att_a":"2"}"#.as_slice(),
        br#"{"privateSeed":12}"#,
        br#"{"att_a":{"seed":1}}"#,
    ] {
        assert!(response_artifact(invalid).is_err());
    }
    assert!(response_artifact(
        &serde_json::to_vec(&json!({"att_a": "a".repeat(MAX_ANSWER_LENGTH + 1)})).unwrap()
    )
    .is_err());
    let too_many: BTreeMap<String, String> =
        (0..17).map(|i| (format!("att_{i}"), "1".into())).collect();
    assert!(response_artifact(&serde_json::to_vec(&too_many).unwrap()).is_err());
    assert!(pack_bundle(Kind::Responses, &vec![b'x'; MAX_ARTIFACT_BYTES + 1]).is_err());
}

#[test]
fn admission_pack_checks_declared_signature_but_does_not_execute_or_score() {
    let good = admission();
    let packed = admission_artifact(&serde_json::to_vec(&good).unwrap()).unwrap();
    assert_eq!(serde_json::from_slice::<Value>(&packed).unwrap(), good);
    let mut tampered = good.clone();
    tampered["payload"] = json!(good["payload"]
        .as_str()
        .unwrap()
        .replace("gs_AlgalFixture", "gs_TamperedFixture"));
    assert!(admission_artifact(&serde_json::to_vec(&tampered).unwrap()).is_err());
    assert!(admission_artifact(&serde_json::to_vec(&public_input()).unwrap()).is_err());
}

#[test]
fn collector_publishes_exact_complete_reordered_bytes_and_explicit_attribution() {
    let dir = Scratch::new();
    let raw = response_artifact(&serde_json::to_vec(&json!({"att_a": "7".repeat(9000)})).unwrap())
        .unwrap();
    let mut files = frames(&dir, Kind::Responses, &raw);
    files.reverse();
    let pins = pins(Kind::Responses, &raw);
    let out = dir.absent("complete.json");
    let meta = execute(&collect_args(&pins, &files, &out)).unwrap();
    assert_eq!(fs::read(&out).unwrap(), raw);
    assert_eq!(meta["scope"]["realm"], hex(&77u128.to_be_bytes()));
    assert_eq!(meta["sharer"], hex(&key().verifying_key().to_bytes()));
    assert_eq!(meta["digest"], hex(&pins.digest));
    assert!(meta["semantics"]
        .as_str()
        .unwrap()
        .contains("not established"));
    assert!(execute(&collect_args(&pins, &files, &out)).is_err());
    assert_eq!(fs::read(&out).unwrap(), raw);
}

#[test]
fn collector_refuses_scope_sharer_kind_digest_signature_and_incomplete_without_output() {
    let dir = Scratch::new();
    let raw = vec![b'7'; 6000];
    let files = frames(&dir, Kind::Responses, &raw);
    for change in 0..7 {
        let mut pin = pins(Kind::Responses, &raw);
        match change {
            0 => pin.network[0] ^= 1,
            1 => pin.realm[0] ^= 1,
            2 => pin.directory[0] ^= 1,
            3 => pin.room[0] ^= 1,
            4 => pin.author = SigningKey::from_bytes(&[43; 32]).verifying_key().to_bytes(),
            5 => pin.kind = Kind::Admission,
            _ => pin.digest[0] ^= 1,
        }
        let out = dir.absent(&format!("refused-{change}"));
        assert!(execute(&collect_args(&pin, &files, &out)).is_err());
        assert!(!Path::new(&out).exists());
    }
    let pin = pins(Kind::Responses, &raw);
    let out = dir.absent("incomplete");
    assert!(execute(&collect_args(&pin, &files[..1], &out)).is_err());
    assert!(!Path::new(&out).exists());
    let mut bad = fs::read(&files[0]).unwrap();
    *bad.last_mut().unwrap() ^= 1;
    let bad_path = dir.file("bad.frame", &bad);
    assert!(execute(&collect_args(&pin, &[bad_path], &out)).is_err());
    assert!(!Path::new(&out).exists());
    assert_eq!(files.len(), 3);
    assert!(files.iter().all(|f| Path::new(f).exists()));
}

#[test]
fn pack_dispatch_is_guarded_and_never_replaces_existing_outputs() {
    let dir = Scratch::new();
    let input = dir.file("responses.json", br#"{"att_a":"12"}"#);
    let output = dir.absent("parts.json");
    let command = args(&["responses", &input, "--out", &output]);
    let meta = execute(&command).unwrap();
    assert_eq!(meta["kind"], "responses");
    let saved = fs::read(&output).unwrap();
    let bundle: Value = serde_json::from_slice(&saved).unwrap();
    assert!(Part::decode(bundle["parts"][0].as_str().unwrap()).is_ok());
    assert!(execute(&command).is_err());
    assert_eq!(fs::read(&output).unwrap(), saved);
    assert!(execute(&args(&[
        "responses",
        &input,
        "--out",
        &output,
        "--key",
        "forbidden"
    ]))
    .is_err());
    assert!(execute(&args(&[
        "responses",
        &input,
        "--out",
        &output,
        "--out",
        "other"
    ]))
    .is_err());
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        let link = dir.absent("input-link");
        symlink(&input, &link).unwrap();
        let absent = dir.absent("must-not-exist");
        assert!(execute(&args(&["responses", &link, "--out", &absent])).is_err());
        assert!(!Path::new(&absent).exists());
        let output_link = dir.absent("output-link");
        symlink(&input, &output_link).unwrap();
        assert!(write_new(Path::new(&output_link), b"replacement").is_err());
        assert_eq!(fs::read(&input).unwrap(), br#"{"att_a":"12"}"#);
    }
}

#[test]
fn challenge_and_admission_pack_dispatch_use_only_public_projections() {
    let dir = Scratch::new();
    for (command, input) in [("challenges", public_input()), ("admission", admission())] {
        let source = dir.file(
            &format!("{command}-input.json"),
            &serde_json::to_vec(&input).unwrap(),
        );
        let out = dir.absent(&format!("{command}-parts.json"));
        execute(&args(&[command, &source, "--out", &out])).unwrap();
        let bundle: Value = serde_json::from_slice(&fs::read(out).unwrap()).unwrap();
        assert!(!bundle["parts"].as_array().unwrap().is_empty());
        for text in bundle["parts"].as_array().unwrap() {
            let Content::Text(_) = event(text.as_str().unwrap(), &key())
                .verify()
                .unwrap()
                .claims()
                .content
                .clone();
        }
    }
}

fn selected_public() -> Vec<u8> {
    public_session(&serde_json::to_vec(&public_input()).unwrap()).unwrap()
}
fn other_public(raw: &[u8]) -> Vec<u8> {
    let mut value: Value = serde_json::from_slice(raw).unwrap();
    value["sessionId"] = json!("gs_OtherSession");
    for challenge in value["challenges"].as_array_mut().unwrap() {
        challenge["sessionId"] = json!("gs_OtherSession");
    }
    canonical_json(&value).into_bytes()
}
fn bundle_artifact(value: &Value) -> Vec<u8> {
    value["parts"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|part| {
            Part::decode(part.as_str().unwrap())
                .unwrap()
                .data()
                .to_vec()
        })
        .collect()
}

#[test]
fn empty_response_envelopes_bind_session_and_exact_selected_artifact_bytes() {
    let raw = selected_public();
    let a = ChallengeSelection::parse(&raw).unwrap();
    let b = ChallengeSelection::parse(&other_public(&raw)).unwrap();
    let first = bound_response_artifact(b"{}", &a).unwrap();
    let second = bound_response_artifact(b"{}", &b).unwrap();
    assert_ne!(first, second);
    assert_ne!(
        pack_bundle(Kind::Responses, &first).unwrap()["digest"],
        pack_bundle(Kind::Responses, &second).unwrap()["digest"]
    );
    assert_eq!(checked_response_map(&first, &a).unwrap(), b"{}");
    assert!(checked_response_map(&first, &b).is_err());
    let alternate = [b" \n".as_slice(), &raw].concat();
    let same_session_different_bytes = ChallengeSelection::parse(&alternate).unwrap();
    assert_eq!(a.session_id, same_session_different_bytes.session_id);
    assert_ne!(a.digest, same_session_different_bytes.digest);
    assert!(checked_response_map(&first, &same_session_different_bytes).is_err());
}

#[test]
fn selected_challenges_refuse_duplicate_fields_ids_foreign_scope_and_invalid_windows() {
    let raw = selected_public();
    let original: Value = serde_json::from_slice(&raw).unwrap();
    for change in 0..10 {
        let mut invalid = original.clone();
        match change {
            0 => invalid["protocol"] = json!("foreign"),
            1 => invalid["kind"] = json!("session"),
            2 => invalid["sessionId"] = json!("invalid"),
            3 => {
                invalid["challenges"][1]["challengeId"] =
                    invalid["challenges"][0]["challengeId"].clone()
            }
            4 => invalid["challenges"][0]["sessionId"] = json!("gs_OtherSession"),
            5 => invalid["challenges"][0]["expiresAt"] = json!("2026-09-19T00:04:00.000Z"),
            6 => invalid["policy"]["challenges"] = json!(2),
            7 => invalid["issuedAt"] = json!("2026-09-19T00:01:00.000Z"),
            8 => invalid["challenges"][0]["verifier"]["private"] = json!("unknown"),
            _ => invalid["challenges"][0]["heldout"]["label"] = json!("private"),
        }
        assert!(
            ChallengeSelection::parse(&serde_json::to_vec(&invalid).unwrap()).is_err(),
            "change {change}"
        );
    }
    let text = std::str::from_utf8(&raw).unwrap();
    for duplicate in [
        text.replacen(
            "\"kind\":\"public-challenges\"",
            "\"kind\":\"public-challenges\",\"kind\":\"public-challenges\"",
            1,
        ),
        text.replacen(
            "\"ttlSeconds\":180",
            "\"ttlSeconds\":180,\"ttlSeconds\":180",
            1,
        ),
        text.replacen("\"poolKey\":", "\"poolKey\":\"bad\",\"poolKey\":", 1),
    ] {
        assert_ne!(duplicate, text);
        assert!(ChallengeSelection::parse(duplicate.as_bytes()).is_err());
    }
    assert!(ChallengeSelection::parse(&vec![b' '; MAX_ARTIFACT_BYTES + 1]).is_err());
    assert!(ChallengeSelection::parse(b"").is_err());
}

#[test]
fn bound_response_preserves_exact_answers_and_rejects_ambiguous_or_foreign_fields() {
    let selection = ChallengeSelection::parse(&selected_public()).unwrap();
    let id = selection.ids.iter().next().unwrap();
    let response = serde_json::to_vec(&json!({id: " +0012\n\tα "})).unwrap();
    let bound = bound_response_artifact(&response, &selection).unwrap();
    assert_eq!(
        checked_response_map(&bound, &selection).unwrap(),
        response_artifact(&response).unwrap()
    );
    let duplicate = format!("{{{id:?}:\"1\",{id:?}:\"2\"}}");
    assert!(bound_response_artifact(duplicate.as_bytes(), &selection).is_err());
    assert!(bound_response_artifact(br#"{"att_foreign":"1"}"#, &selection).is_err());
    let original: Value = serde_json::from_slice(&bound).unwrap();
    for change in 0..6 {
        let mut invalid = original.clone();
        match change {
            0 => invalid["extra"] = json!(true),
            1 => invalid["sessionId"] = json!("gs_OtherSession"),
            2 => invalid["challengeDigest"] = json!("00".repeat(32)),
            3 => invalid["responses"] = json!({"att_foreign":"1"}),
            4 => invalid["protocol"] = json!("clankdar-room-responses/2"),
            _ => invalid["kind"] = json!("admission"),
        }
        assert!(checked_response_map(&serde_json::to_vec(&invalid).unwrap(), &selection).is_err());
    }
    let text = std::str::from_utf8(&bound).unwrap();
    let duplicate = format!("{{\"kind\":\"responses\",{}", &text[1..]);
    assert!(checked_response_map(duplicate.as_bytes(), &selection).is_err());
    let mut without_answers = original.clone();
    without_answers["responses"] = Value::Null;
    let duplicate_answers = canonical_json(&without_answers).replace(
        "\"responses\":null",
        &format!("\"responses\":{{{id:?}:\"1\",{id:?}:\"2\"}}"),
    );
    // Duplicate answer IDs are rejected by the embedded Responses decoder too.
    assert!(checked_response_map(duplicate_answers.as_bytes(), &selection).is_err());
    assert!(bound_response_artifact(&vec![b' '; MAX_ARTIFACT_BYTES + 1], &selection).is_err());
    assert!(checked_response_map(&vec![b' '; MAX_ARTIFACT_BYTES + 1], &selection).is_err());
    assert!(bound_response_artifact(
        &serde_json::to_vec(&json!({id: "x".repeat(MAX_ANSWER_LENGTH + 1)})).unwrap(),
        &selection
    )
    .is_err());
}

#[test]
fn bound_exchange_collect_and_checked_extraction_preserve_no_overwrite_and_selection() {
    let dir = Scratch::new();
    let selected = selected_public();
    let challenge = dir.file("challenge.json", &selected);
    let other = dir.file("other.json", &other_public(&selected));
    let answers = dir.file("answers.json", b"{}");
    let parts = dir.absent("parts.json");
    let report = execute(&args(&[
        "responses",
        &answers,
        "--challenges",
        &challenge,
        "--out",
        &parts,
    ]))
    .unwrap();
    assert_eq!(report["correlation"], "selected_challenges");
    let bundle: Value = serde_json::from_slice(&fs::read(parts).unwrap()).unwrap();
    let bound = bundle_artifact(&bundle);
    let inputs = frames(&dir, Kind::Responses, &bound);
    let collected = dir.absent("collected.json");
    execute(&collect_args(
        &pins(Kind::Responses, &bound),
        &inputs,
        &collected,
    ))
    .unwrap();
    let output = dir.absent("checked-map.json");
    assert!(execute(&args(&[
        "response-map",
        &collected,
        "--challenges",
        &other,
        "--out",
        &output
    ]))
    .is_err());
    assert!(!Path::new(&output).exists());
    let report = execute(&args(&[
        "response-map",
        &collected,
        "--challenges",
        &challenge,
        "--out",
        &output,
    ]))
    .unwrap();
    assert_eq!(report["correlation"], "selected_challenges");
    assert_eq!(fs::read(&output).unwrap(), b"{}");
    assert!(execute(&args(&[
        "response-map",
        &collected,
        "--challenges",
        &challenge,
        "--out",
        &output
    ]))
    .is_err());
    assert_eq!(fs::read(&output).unwrap(), b"{}");
    assert_eq!(fs::read(&collected).unwrap(), bound);
    let foreign = dir.file("foreign.json", br#"{"att_foreign":"1"}"#);
    let refused = dir.absent("refused-parts.json");
    assert!(execute(&args(&[
        "responses",
        &foreign,
        "--challenges",
        &challenge,
        "--out",
        &refused
    ]))
    .is_err());
    assert!(!Path::new(&refused).exists());
}

#[test]
fn legacy_maps_remain_byte_compatible_and_never_acquire_bound_labels() {
    let dir = Scratch::new();
    let raw = br#"{"att_old":" 12\n"}"#;
    let source = dir.file("legacy.json", raw);
    let output = dir.absent("legacy-parts.json");
    let report = execute(&args(&["responses", &source, "--out", &output])).unwrap();
    assert_eq!(report["correlation"], "unbound_legacy");
    let bundle: Value = serde_json::from_slice(&fs::read(output).unwrap()).unwrap();
    assert_eq!(bundle_artifact(&bundle), response_artifact(raw).unwrap());
    assert!(bundle["sessionId"].is_null());
    assert!(bundle["challengeDigest"].is_null());
    let map = dir.absent("legacy-map.json");
    assert!(execute(&args(&["response-map", &source, "--out", &map])).is_err());
    assert!(!Path::new(&map).exists());
    let report = execute(&args(&[
        "response-map",
        &source,
        "--unbound-legacy",
        "--out",
        &map,
    ]))
    .unwrap();
    assert_eq!(report["correlation"], "unbound_legacy");
    assert!(report["sessionId"].is_null());
    let challenge = dir.file("challenge.json", &selected_public());
    let refused = dir.absent("never-bound.json");
    assert!(execute(&args(&[
        "response-map",
        &source,
        "--challenges",
        &challenge,
        "--out",
        &refused
    ]))
    .is_err());
    assert!(execute(&args(&[
        "response-map",
        &source,
        "--challenges",
        &challenge,
        "--unbound-legacy",
        "--out",
        &refused
    ]))
    .is_err());
    assert!(!Path::new(&refused).exists());
}
