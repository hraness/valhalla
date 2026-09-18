//! The challenge transcript and dedup key from the independent Python oracle.

use std::fs;
use std::path::Path;

use vhalla_botcaptcha::challenge::{Algorithm, Challenge, Purpose, Requirement};
use vhalla_botcaptcha::hashcash::{leading_zero_bits, work_digest};
use vhalla_core::{RealmId, RoomId};
use vhalla_witness::hash::ManifestHash;
use vhalla_witness::manifest::WorkContract;
use vhalla_witness::vectors::hex;

fn field(json: &str, key: &str) -> String {
    let needle = format!("\"{key}\": ");
    let start = json.find(&needle).unwrap_or_else(|| panic!("{key}")) + needle.len();
    let rest = &json[start..];
    let end = rest.find([',', '\n']).unwrap();
    rest[..end].trim().trim_matches('"').to_string()
}

#[test]
fn python_challenge_transcript_and_dedup_key_match_byte_for_byte() {
    let json = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vectors/witness-v1.json"),
    )
    .unwrap();
    let challenge = Challenge {
        version: 1,
        algorithm: Algorithm::Witness,
        challenge_id: core::array::from_fn(|index| index as u8),
        issuer_key: [7; 32],
        subject_key: [9; 32],
        realm: RealmId(1),
        room: RoomId(2),
        purpose: Purpose::RateLimitRelief,
        task_manifest_hash: ManifestHash([1; 32]),
        issued_at: 1_000_000,
        expires_at: 1_000_600,
        requirement: Requirement::Witness(WorkContract {
            useful_floor: 1,
            total_ceiling: 4000,
            require_passed: false,
        }),
        signature: [0; 64],
    };
    assert_eq!(hex(&challenge.body()), field(&json, "challenge_body_hex"));
    assert_eq!(
        hex(&challenge.transcript()),
        field(&json, "challenge_transcript_hex")
    );
    assert_eq!(hex(&challenge.scope_key()), field(&json, "dedup_key_hex"));
    assert_eq!(Challenge::decode(&challenge.encode()).unwrap(), challenge);
    let work = work_digest(challenge.hash(), [9; 32], 12_345);
    assert_eq!(hex(&work), field(&json, "hashcash_work_digest_hex"));
    assert_eq!(
        leading_zero_bits(&work).to_string(),
        field(&json, "hashcash_leading_zero_bits")
    );
}
