//! The frozen v1 session vectors. Every record in `tests/vectors/game-v1-session-*.txt`
//! is replayed through a fresh `Session` and `Receiver<PlatonikV1>` built only
//! from the committed hex, and every digest, checkpoint, and receipt the
//! receiver derives must equal the committed value. From here on a change to
//! any encoding, domain, or derivation fails this test rather than shipping.
//!
//! Regenerate with
//! `cargo run -p vhalla-game-platonik --example game_session_vectors --features oracle`
//! and only with a recorded reason.

use std::collections::BTreeMap;
use std::path::Path;

use vhalla_game_platonik::engine::GameEngine;
use vhalla_game_platonik::ids::{CheckpointHash, GameManifestHash, SessionKey};
use vhalla_game_platonik::platonik::PlatonikV1;
use vhalla_game_platonik::receiver::{Receiver, ReceiverPolicy};
use vhalla_game_platonik::record::{GameRecord, RecordKind};
use vhalla_game_platonik::session::Session;
use vhalla_game_platonik::wire::{
    decode_checkpoint, decode_game_manifest, decode_session_open, encode_checkpoint,
    encode_game_manifest, encode_session_open, EventBody,
};
use vhalla_witness::hash::{digest, RECEIPT_DOMAIN};
use vhalla_witness::manifest::ValidManifest;
use vhalla_witness::platform::{ReceiptBinding, WorkAllowance};
use vhalla_witness::vectors::{hex, unhex};

/// The `key: value` lines of one vector file.
fn parse(text: &str) -> BTreeMap<String, String> {
    let mut fields = BTreeMap::new();
    for line in text.lines() {
        let Some((key, value)) = line.split_once(": ") else {
            continue;
        };
        assert!(
            fields.insert(key.to_string(), value.to_string()).is_none(),
            "duplicate key {key}"
        );
    }
    fields
}

fn field<'a>(fields: &'a BTreeMap<String, String>, key: &str) -> &'a str {
    fields
        .get(key)
        .unwrap_or_else(|| panic!("missing field {key}"))
}

fn bytes(fields: &BTreeMap<String, String>, key: &str) -> Vec<u8> {
    unhex(field(fields, key)).unwrap_or_else(|| panic!("bad hex in {key}"))
}

fn hash32(fields: &BTreeMap<String, String>, key: &str) -> [u8; 32] {
    let raw = bytes(fields, key);
    let mut out = [0_u8; 32];
    assert_eq!(raw.len(), 32, "{key} is not 32 bytes");
    out.copy_from_slice(&raw);
    out
}

fn policy() -> ReceiverPolicy {
    ReceiverPolicy {
        max_replays: 64,
        max_work: u64::MAX,
        max_steps: u64::MAX,
    }
}

/// The receipt the final seal's replay produces, derived the way the receiver
/// derives it from the seal the vector carries.
fn final_receipt(session: &Session, record: &GameRecord) -> Vec<u8> {
    let event = vhalla_game_platonik::wire::decode_game_event(&record.body).unwrap();
    let plan = session.plan_seal(&event).unwrap();
    let manifest = ValidManifest::validate(plan.manifest.clone()).unwrap();
    let allowance = WorkAllowance {
        max_total: manifest
            .fuel_total()
            .min(session.manifest().limits.replay.max_total),
    };
    let binding = ReceiptBinding {
        challenge_id: session.key().0,
        subject_key: session.host(),
    };
    PlatonikV1
        .replay(
            session.world(),
            &manifest,
            plan.candidate.clone(),
            allowance,
            plan.through_tick,
            binding,
        )
        .unwrap()
        .receipt
        .encode()
}

/// Rebuilds one vector's session from its hex alone and checks every value.
fn replay_vector(name: &str) {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/vectors")
        .join(name);
    let text = std::fs::read_to_string(&path).unwrap();
    let fields = parse(&text);
    // The manifest and the opening round trip and hash to their committed ids.
    let manifest_raw = bytes(&fields, "game_manifest");
    let manifest = decode_game_manifest(&manifest_raw).unwrap();
    assert_eq!(encode_game_manifest(&manifest), manifest_raw, "{name}");
    assert_eq!(
        manifest.hash(),
        GameManifestHash(hash32(&fields, "game_manifest_hash")),
        "{name}"
    );
    assert_eq!(
        manifest.hash(),
        GameManifestHash::of(&manifest_raw),
        "{name}"
    );
    let open_raw = bytes(&fields, "session_open");
    let open = decode_session_open(&open_raw).unwrap();
    assert_eq!(encode_session_open(&open), open_raw, "{name}");
    let key = SessionKey(hash32(&fields, "session_key"));
    assert_eq!(open.key(), key, "{name}");
    assert_eq!(SessionKey::of(&open_raw), key, "{name}");
    assert_eq!(open.manifest, manifest.hash(), "{name}");

    let realm = open.realm;
    let mut session = Session::open(manifest, open, realm).unwrap();
    let mut receiver = Receiver::new(PlatonikV1, policy());
    let count: usize = field(&fields, "record_count").parse().unwrap();
    let mut seals = 0_usize;
    let mut receipt = Vec::new();
    for index in 0..count {
        let at = |suffix: &str| format!("record[{index}].{suffix}");
        let raw = bytes(&fields, &at("record"));
        let record = GameRecord::decode(&raw).unwrap();
        assert_eq!(record.encode(), raw, "{name} record {index} round trip");
        record.verify().unwrap();
        assert_eq!(
            record.kind as u8,
            field(&fields, &at("kind")).parse::<u8>().unwrap()
        );
        assert_eq!(record.kind, RecordKind::Event, "{name} record {index}");
        assert_eq!(record.session, key, "{name} record {index}");
        assert_eq!(hex(&record.signer), field(&fields, &at("signer")));
        let event = vhalla_game_platonik::wire::decode_game_event(&record.body).unwrap();
        assert_eq!(
            hex(&event.digest().0),
            field(&fields, &at("event_digest")),
            "{name} record {index}"
        );
        assert_eq!(event.author, record.signer, "{name} record {index}");
        let is_seal = matches!(event.body, EventBody::Seal { .. });
        assert_eq!(
            is_seal,
            fields.contains_key(&at("checkpoint")),
            "{name} record {index} seal fields"
        );
        let is_final = is_seal && field(&fields, &at("final")) == "1";
        if is_final {
            receipt = final_receipt(&session, &record);
        }
        let step = index as u64 + 1;
        let verified = receiver.admit(&mut session, &record, step).unwrap();
        if !is_seal {
            assert!(verified.is_none(), "{name} record {index} is not a seal");
            continue;
        }
        seals += 1;
        let verified = verified.expect("a seal produces a verified checkpoint");
        assert_eq!(
            verified.final_receipt_hash().map(|hash| hash.0),
            is_final.then(|| hash32(&fields, "receipt_hash")),
            "{name}: final receipt comes from the receiver's charged replay"
        );
        // The committed checkpoint bytes hash to the committed id and to the
        // one the receiver reproduced from replay alone.
        let checkpoint_raw = bytes(&fields, &at("checkpoint"));
        let checkpoint = decode_checkpoint(&checkpoint_raw).unwrap();
        assert_eq!(encode_checkpoint(&checkpoint), checkpoint_raw);
        let committed = CheckpointHash(hash32(&fields, &at("checkpoint_hash")));
        assert_eq!(checkpoint.hash(), committed, "{name} checkpoint {index}");
        assert_eq!(CheckpointHash::of(&checkpoint_raw), committed);
        assert_eq!(verified.hash(), committed, "{name} checkpoint {index}");
        assert_eq!(verified.through_tick(), checkpoint.through_tick);
        assert_eq!(verified.segment(), checkpoint.segment);
        assert_eq!(verified.session(), key);
        assert_eq!(verified.work(), checkpoint.work);
        assert_eq!(verified.is_final(), is_final, "{name} checkpoint {index}");
        assert_eq!(
            session.segments().last().map(|s| s.2),
            Some(committed),
            "{name} the seal is committed"
        );
    }
    assert!(seals > 0, "{name} seals at least once");
    assert_eq!(hex(&receipt), field(&fields, "receipt"), "{name} receipt");
    assert_eq!(receipt.len(), 180, "{name} receipt is 180 bytes");
    assert_eq!(
        hex(&digest(RECEIPT_DOMAIN, &receipt)),
        field(&fields, "receipt_hash"),
        "{name} receipt hash"
    );
}

#[test]
fn the_replay_session_vector_is_frozen() {
    replay_vector("game-v1-session-replay.txt");
}

#[test]
fn the_live_session_vector_is_frozen() {
    replay_vector("game-v1-session-live.txt");
}

#[test]
fn receiver_step_limit_refuses_before_admission_and_preserves_its_frontier() {
    let fields = parse(include_str!("vectors/game-v1-session-replay.txt"));
    let manifest = decode_game_manifest(&bytes(&fields, "game_manifest")).unwrap();
    let open = decode_session_open(&bytes(&fields, "session_open")).unwrap();
    let realm = open.realm;
    let mut session = Session::open(manifest, open, realm).unwrap();
    let record = GameRecord::decode(&bytes(&fields, "record[0].record")).unwrap();
    let mut limits = policy();
    limits.max_steps = 1;
    let mut receiver = Receiver::new(PlatonikV1, limits);
    assert!(matches!(
        receiver.admit(&mut session, &record, 2),
        Err(vhalla_game_platonik::receiver::ReceiverError::BudgetExhausted)
    ));
    assert_eq!(receiver.step(), 0);
    assert!(receiver.admit(&mut session, &record, 1).is_ok());
    assert_eq!(receiver.step(), 1);
    // A second session shares the receiver's logical deadline. Starting
    // it does not reset that clock or silently give it a fresh interval.
    let other = parse(include_str!("vectors/game-v1-session-live.txt"));
    let manifest = decode_game_manifest(&bytes(&other, "game_manifest")).unwrap();
    let open = decode_session_open(&bytes(&other, "session_open")).unwrap();
    let realm = open.realm;
    let mut other_session = Session::open(manifest, open, realm).unwrap();
    assert_ne!(session.key(), other_session.key());
    let record = GameRecord::decode(&bytes(&other, "record[0].record")).unwrap();
    assert!(matches!(
        receiver.admit(&mut other_session, &record, 2),
        Err(vhalla_game_platonik::receiver::ReceiverError::BudgetExhausted)
    ));
    assert!(receiver.admit(&mut other_session, &record, 1).is_ok());
}
