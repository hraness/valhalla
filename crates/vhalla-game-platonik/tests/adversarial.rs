//! `mutate_every_field`: the threat model's "tampered or rehashed checkpoint
//! or receipt" row turned into a test.
//!
//! The frozen live session vector is rebuilt exactly as `session_vectors.rs`
//! rebuilds it, from the committed hex alone, and then attacked in three ways.
//!
//! 1. Every single byte of every record's encoding is flipped, one bit at a
//!    time. Each candidate must be refused: by the decoder, by the carrier's
//!    signature check, or by admission. None may be accepted, and none may
//!    panic. The genuine record is admitted after each sweep, which is also
//!    the proof that a refused candidate left the session bit-identical.
//! 2. Every field of every sealed checkpoint is mutated one at a time, the
//!    mutated checkpoint is re-hashed into a freshly host-signed seal, and a
//!    fresh session replayed to that point must refuse it as `ReplayMismatch`,
//!    end `Unresolved { ReplayMismatch }`, and retain the forged seal. This is
//!    the check that a host cannot move any value in a checkpoint, because the
//!    receiver reproduces all of them from replay.
//! 3. The unmodified vector is replayed once more at the end and every
//!    committed checkpoint hash still reproduces, so the harness is not
//!    passing because everything fails.
//!
//! The host key is the example's fixed `HOST_SEED` of `[1; 32]`
//! (`examples/game_session_vectors.rs`), which is asserted against the
//! vector's own seal signer rather than assumed.

use std::collections::BTreeMap;
use std::path::Path;

use ed25519_dalek::SigningKey;
use vhalla_core::{Epoch, RealmId};
use vhalla_game_platonik::ids::{CheckpointHash, GameManifestHash, SessionKey};
use vhalla_game_platonik::platonik::PlatonikV1;
use vhalla_game_platonik::receiver::{Receiver, ReceiverError, ReceiverPolicy};
use vhalla_game_platonik::record::{GameRecord, RecordKind};
use vhalla_game_platonik::session::{Rejection, Session, State};
use vhalla_game_platonik::wire::{
    decode_checkpoint, decode_game_event, decode_game_manifest, decode_session_open, Checkpoint,
    EventBody, ForkReason, GameEvent,
};
use vhalla_ledger::{EventDigest, StateRoot};
use vhalla_witness::hash::{ManifestHash, ProgramHash, StateHash};
use vhalla_witness::vectors::unhex;
use vhalla_witness::vm::RunStatus;

/// The example's fixed host seed; the vector's seal signer is checked against it.
const HOST_SEED: [u8; 32] = [1; 32];

/// The `key: value` lines of the vector, as `session_vectors.rs` parses them.
fn parse(text: &str) -> BTreeMap<String, String> {
    let mut fields = BTreeMap::new();
    for line in text.lines() {
        if let Some((key, value)) = line.split_once(": ") {
            assert!(
                fields.insert(key.to_string(), value.to_string()).is_none(),
                "duplicate key {key}"
            );
        }
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

/// The live session vector's fields.
fn vector() -> BTreeMap<String, String> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/vectors")
        .join("game-v1-session-live.txt");
    parse(&std::fs::read_to_string(&path).expect("a readable vector"))
}

/// A fresh session and receiver built from the committed manifest and opening
/// alone, exactly as `session_vectors::replay_vector` builds them.
fn fresh(fields: &BTreeMap<String, String>) -> (Session, Receiver<PlatonikV1>) {
    let manifest = decode_game_manifest(&bytes(fields, "game_manifest")).expect("a manifest");
    assert_eq!(
        manifest.hash(),
        GameManifestHash(hash32(fields, "game_manifest_hash"))
    );
    let open = decode_session_open(&bytes(fields, "session_open")).expect("an opening");
    assert_eq!(open.key(), SessionKey(hash32(fields, "session_key")));
    let realm = open.realm;
    (
        Session::open(manifest, open, realm).expect("an opened session"),
        Receiver::new(PlatonikV1, policy()),
    )
}

/// The record at one index.
fn record_at(fields: &BTreeMap<String, String>, index: usize) -> (Vec<u8>, GameRecord) {
    let raw = bytes(fields, &format!("record[{index}].record"));
    let record = GameRecord::decode(&raw).expect("a vector record");
    (raw, record)
}

/// A fresh session with records `0..upto` admitted honestly.
fn replayed_to(fields: &BTreeMap<String, String>, upto: usize) -> (Session, Receiver<PlatonikV1>) {
    let (mut session, mut receiver) = fresh(fields);
    for index in 0..upto {
        let (_, record) = record_at(fields, index);
        receiver
            .admit(&mut session, &record, index as u64 + 1)
            .unwrap_or_else(|e| panic!("record {index} must admit, got {e:?}"));
    }
    (session, receiver)
}

/// Replays the unmodified vector and checks every committed value, so a pass
/// above cannot come from a session that refuses everything.
fn unmodified_still_verifies(fields: &BTreeMap<String, String>) {
    let (mut session, mut receiver) = fresh(fields);
    let count: usize = field(fields, "record_count").parse().expect("a count");
    let mut seals = 0_usize;
    for index in 0..count {
        let (_, record) = record_at(fields, index);
        let verified = receiver
            .admit(&mut session, &record, index as u64 + 1)
            .unwrap_or_else(|e| panic!("record {index} must admit, got {e:?}"));
        let key = format!("record[{index}].checkpoint_hash");
        match verified {
            Some(verified) => {
                seals += 1;
                assert_eq!(verified.hash(), CheckpointHash(hash32(fields, &key)));
            }
            None => assert!(!fields.contains_key(&key), "record {index} sealed nothing"),
        }
    }
    assert!(seals > 0, "the vector seals at least once");
    assert_eq!(session.state(), State::Finished);
}

fn flip32(mut hash: [u8; 32]) -> [u8; 32] {
    hash[0] ^= 1;
    hash
}

fn other_status(status: RunStatus) -> RunStatus {
    match status {
        RunStatus::Complete => RunStatus::FuelExhausted,
        RunStatus::FuelExhausted | RunStatus::ActivationLimit => RunStatus::Complete,
    }
}

/// Every field of a checkpoint, mutated one at a time. The ledger struct is
/// broken out field by field because it is the part a realm finality layer
/// would sign unchanged.
fn one_field_at_a_time(base: &Checkpoint) -> Vec<(String, Checkpoint)> {
    let mut out: Vec<(String, Checkpoint)> = Vec::new();
    let mut with = |name: &str, mutated: Checkpoint| out.push((name.to_string(), mutated));

    let mut value = base.clone();
    value.session = SessionKey(flip32(value.session.0));
    with("session", value);

    let mut value = base.clone();
    value.ledger.realm = RealmId(value.ledger.realm.0 ^ 1);
    with("ledger.realm", value);

    let mut value = base.clone();
    value.ledger.epoch = Epoch(value.ledger.epoch.0 ^ 1);
    with("ledger.epoch", value);

    let mut value = base.clone();
    value.ledger.head = EventDigest(flip32(value.ledger.head.0));
    with("ledger.head", value);

    let mut value = base.clone();
    value.ledger.state_root = StateRoot(flip32(value.ledger.state_root.0));
    with("ledger.state_root", value);

    let mut value = base.clone();
    value.ledger.height ^= 1;
    with("ledger.height", value);

    let mut value = base.clone();
    value.parent = flip32(value.parent);
    with("parent", value);

    let mut value = base.clone();
    value.segment ^= 1;
    with("segment", value);

    let mut value = base.clone();
    value.segment_manifest = ManifestHash(flip32(value.segment_manifest.0));
    with("segment_manifest", value);

    let mut value = base.clone();
    value.program = ProgramHash(flip32(value.program.0));
    with("program", value);

    let mut value = base.clone();
    value.through_tick ^= 1;
    with("through_tick", value);

    for case in 0..base.cases.len() {
        let mut value = base.clone();
        value.cases[case].state = StateHash(flip32(value.cases[case].state.0));
        with(&format!("cases[{case}].state"), value);

        let mut value = base.clone();
        value.cases[case].trace = flip32(value.cases[case].trace);
        with(&format!("cases[{case}].trace"), value);

        let mut value = base.clone();
        value.cases[case].ledger_total ^= 1;
        with(&format!("cases[{case}].ledger_total"), value);

        let mut value = base.clone();
        value.cases[case].status = other_status(value.cases[case].status);
        with(&format!("cases[{case}].status"), value);
    }

    let mut value = base.clone();
    value.work.useful ^= 1;
    with("work.useful", value);

    let mut value = base.clone();
    value.work.total ^= 1;
    with("work.total", value);

    out
}

#[test]
fn mutate_every_field() {
    let fields = vector();
    let count: usize = field(&fields, "record_count").parse().expect("a count");
    let host = SigningKey::from_bytes(&HOST_SEED);

    // (a) Every bit of every record, against a session at exactly the point
    // that record belongs to. The honest record is admitted afterwards, so a
    // sweep that quietly corrupted the session would fail here rather than
    // pass silently.
    let (mut session, mut receiver) = fresh(&fields);
    let mut candidates = 0_usize;
    let mut refused_by_decoder = 0_usize;
    let mut refused_by_signature = 0_usize;
    let mut refused_by_admission = 0_usize;
    for index in 0..count {
        let (raw, genuine) = record_at(&fields, index);
        let step = index as u64 + 1;
        for at in 0..raw.len() {
            for bit in 0..8_u32 {
                let mut candidate = raw.clone();
                candidate[at] ^= 1 << bit;
                candidates += 1;
                let Ok(forged) = GameRecord::decode(&candidate) else {
                    refused_by_decoder += 1;
                    continue;
                };
                if forged.verify().is_err() {
                    refused_by_signature += 1;
                    continue;
                }
                let outcome = receiver.admit(&mut session, &forged, step);
                assert!(
                    outcome.is_err(),
                    "record {index} byte {at} bit {bit} was accepted"
                );
                refused_by_admission += 1;
            }
        }
        receiver
            .admit(&mut session, &genuine, step)
            .unwrap_or_else(|e| panic!("record {index} must still admit, got {e:?}"));
    }
    assert_eq!(
        session.state(),
        State::Finished,
        "the honest replay finished"
    );
    assert_eq!(
        candidates,
        refused_by_decoder + refused_by_signature + refused_by_admission
    );
    assert!(refused_by_decoder > 0 && refused_by_signature > 0);
    println!(
        "bit flips: {candidates} candidates, {refused_by_decoder} refused by the decoder, \
{refused_by_signature} by the signature, {refused_by_admission} by admission"
    );

    // (b) Every checkpoint field, re-hashed into a freshly signed seal.
    let mut forged_seals = 0_usize;
    for index in 0..count {
        let (_, record) = record_at(&fields, index);
        let event = decode_game_event(&record.body).expect("a vector event");
        let EventBody::Seal {
            segment,
            through_tick,
            order,
            ..
        } = &event.body
        else {
            continue;
        };
        assert_eq!(
            record.signer,
            host.verifying_key().to_bytes(),
            "the vector's seals are signed by the fixed [1; 32] host seed"
        );
        let committed = bytes(&fields, &format!("record[{index}].checkpoint"));
        let checkpoint = decode_checkpoint(&committed).expect("a vector checkpoint");
        assert_eq!(
            checkpoint.hash(),
            CheckpointHash(hash32(&fields, &format!("record[{index}].checkpoint_hash")))
        );
        for (name, mutated) in one_field_at_a_time(&checkpoint) {
            assert_ne!(
                mutated.hash(),
                checkpoint.hash(),
                "seal {index} field {name} did not move the hash"
            );
            let forged = GameEvent {
                body: EventBody::Seal {
                    segment: *segment,
                    through_tick: *through_tick,
                    order: order.clone(),
                    checkpoint: mutated.hash(),
                },
                ..event.clone()
            };
            let signed = GameRecord::sign(
                RecordKind::Event,
                forged.session,
                vhalla_game_platonik::wire::encode_game_event(&forged),
                &host,
            )
            .expect("a signed forgery");
            signed.verify().expect("the forgery is well signed");
            let (mut session, mut receiver) = replayed_to(&fields, index);
            let outcome = receiver.admit(&mut session, &signed, index as u64 + 1);
            assert_eq!(
                outcome.err(),
                Some(ReceiverError::Session(Rejection::ReplayMismatch)),
                "seal {index} field {name} was not refused as a replay mismatch"
            );
            assert_eq!(
                session.state(),
                State::Unresolved(ForkReason::ReplayMismatch),
                "seal {index} field {name} left the session resolved"
            );
            assert!(
                session.retained().contains(&forged.digest().0),
                "seal {index} field {name} did not retain the forged seal"
            );
            forged_seals += 1;
        }
    }
    assert!(forged_seals > 0, "the vector carries at least one seal");
    println!("checkpoint forgeries: {forged_seals} single-field seals refused");

    // (c) The harness is not vacuous.
    unmodified_still_verifies(&fields);
}
